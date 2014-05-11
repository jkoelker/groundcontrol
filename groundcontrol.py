#!/usr/bin/env python
# -*- coding: utf-8 -*-

import eventlet
eventlet.monkey_patch()

import argparse
import functools
import logging
import time
import os

import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import docker


LOG = logging.getLogger(__name__)
LOG.warn = LOG.warning

CONFIG = intern('Config')
DIE = intern('die')
ENV = intern('Env')
ID = intern('id')
IMAGE = intern('Image')
IPADDRESS = intern('IPAddress')
NAME = intern('Name')
NETWORK_SETTINGS = intern('NetworkSettings')
RUNNING = intern('Running')
STATE = intern('State')
STATUS = intern('status')
START = intern('start')


class Container(object):
    def __init__(self, container, env_ip_key, env_name_key, env_service_key,
                 env_skip_key, skip_images=None, skip_services=None):

        self._container = container
        self._env_ip_key = env_ip_key
        self._env_name_key = env_name_key
        self._env_service_key = env_service_key
        self._env_skip_key = env_skip_key

        if skip_images is None:
            skip_images = []

        if skip_services is None:
            skip_services = []

        self._skip_images = skip_images
        self._skip_services = skip_services

        env = container[CONFIG].get(ENV)

        if not env:
            env = []

        self._env = dict(e.split('=') for e in env)

    def env(self, key):
        return self._env.get(key)

    @property
    def should_create_records(self):
        return not any((self.image in self._skip_images,
                        self.service in self._skip_services,
                        self._env_skip_key in self._env))

    @property
    def image(self):
        return self._container[CONFIG][IMAGE]

    @property
    def ip(self):
        ip = self.env(self._env_ip_key)

        if ip:
            return ip.strip()

        return self._container[NETWORK_SETTINGS][IPADDRESS]

    @property
    def name(self):
        name = self.env(self._env_name_key)

        if name:
            return name.strip()

        return self._container[NAME].strip('/')

    @property
    def running(self):
        return self._container[STATE][RUNNING]

    @property
    def service(self):
        service = self.env(self._env_service_key)

        if service:
            return service.strip()

        return self._container[CONFIG][IMAGE].split('/')[-1].split(':')[0]


class DNS(object):
    def __init__(self, identity, nameserver, origin, resolver_timeout,
                 tsig_key_path, ttl, update_timeout):
        self._nameserver = nameserver
        self._ttl = ttl
        self._update_timeout = update_timeout
        self._resolver_timeout = resolver_timeout

        self._origin = dns.name.from_text(origin)
        self._identity = dns.name.from_text(identity, self._origin)

        LOG.info('Managing records in %s' % self._origin)

        with open(tsig_key_path) as tsig_key:
            line = tsig_key.readline()
            parts = line.split()
            self._keyring = dns.tsigkeyring.from_text({parts[0]: parts[-1]})

    def _query(self, qname, rdtype, rdclass=dns.rdataclass.IN,
               one_record=False):
        msg = dns.message.make_query(qname, rdtype, rdclass)
        response = dns.query.tcp(msg, self._nameserver,
                                 self._resolver_timeout, 53)

        if one_record:
            rrset = response.get_rrset(response.answer, qname, rdclass, rdtype)

            if not rrset:
                return

            return rrset.items[0]

        return dict((rrset.rdtype, rrset) for rrset in response.answer)

    def _update(self, update):
        response = dns.query.tcp(update, self._nameserver,
                                 timeout=self._update_timeout)
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            LOG.warn(dns.rcode.to_text(rcode))

    @property
    def containers(self):
        identity_rrsets = self._query(self._identity, dns.rdatatype.SRV)
        identity_rrset = identity_rrsets.get(dns.rdatatype.SRV, [])
        return [str(r.target - self._identity) for r in identity_rrset]

    def add(self, container_id, service, name, ip):
        LOG.info('Adding records for container: %s name: %s, ip: %s' %
                 (container_id, name, ip))
        uuid_qname = dns.name.from_text(container_id, self._identity)
        service_qname = dns.name.from_text(service, self._origin)
        name_qname = dns.name.from_text(name, self._identity)

        update = dns.update.Update(self._origin, keyring=self._keyring)
        update.add(self._identity, self._ttl, dns.rdatatype.SRV,
                   '10 10 0 %s' % uuid_qname)
        update.add(name_qname, self._ttl, dns.rdatatype.SRV,
                   '10 10 0 %s' % service_qname)
        update.add(uuid_qname, self._ttl, dns.rdatatype.CNAME,
                   str(name_qname))
        update.add(service_qname, self._ttl, dns.rdatatype.A, ip)
        update.add(name_qname, self._ttl, dns.rdatatype.A, ip)

        self._update(update)

    def delete(self, container_id):
        LOG.info('Deleting records for container: %s' % container_id)

        uuid_qname = dns.name.from_text(container_id, self._identity)
        identity_rrset = self._query(self._identity, dns.rdatatype.SRV)
        update = dns.update.Update(self._origin, keyring=self._keyring)

        for srv in identity_rrset.get(dns.rdatatype.SRV, []):
            if srv.target == uuid_qname:
                update.delete(self._identity, srv)

        uuid_rdata = self._query(uuid_qname, dns.rdatatype.CNAME,
                                 one_record=True)

        if not uuid_rdata:
            LOG.warn('No records found for container: %s' % container_id)
            return

        name_qname = uuid_rdata.target
        name_rrsets = self._query(name_qname, dns.rdatatype.ANY)
        name_rdata = name_rrsets[dns.rdatatype.A].items[0]

        service_name_rdata = name_rrsets[dns.rdatatype.SRV].items[0]
        service_rrsets = self._query(service_name_rdata.target,
                                     dns.rdatatype.A)
        service_rdata = service_rrsets.get(dns.rdatatype.A, [])

        update.delete(service_name_rdata.target, dns.rdatatype.A)
        update.delete(uuid_qname, dns.rdatatype.CNAME)
        update.delete(name_qname, dns.rdatatype.A)
        update.delete(name_qname, dns.rdatatype.SRV)

        for rdata in service_rdata:
            if rdata.address != name_rdata.address:
                update.add(service_name_rdata.target, self._ttl, rdata)

        self._update(update)


def get_container(container_id, docker_client, container_wrapper):
    try:
        container_info = docker_client.inspect_container(container_id)

    except docker.APIError:
        return

    return container_wrapper(container_info)


def add_container(container_id, docker_client, dns_client, container_wrapper):
    container = get_container(container_id, docker_client, container_wrapper)

    if (not container or
            not container.running or
            not container.should_create_records):
        return

    # NOTE(jkoelker) https://github.com/rthalley/dnspython/issues/44
    ip = str(container.ip)

    dns_client.add(container_id, container.service, container.name, ip)


def delete_container(container_id, docker_client, dns_client,
                     container_wrapper):
    dns_client.delete(container_id)


def monitor_dns(docker_client, dns_client, container_wrapper,
                beat_interval=None):
    if beat_interval is None:
        beat_interval = dns_client._ttl - (dns_client._ttl / 4.0)

    while True:
        docker_containers = set([c['Id'][:10]
                                 for c in docker_client.containers()])
        dns_containers = set(dns_client.containers)

        offline_containers = dns_containers - docker_containers
        new_containers = docker_containers - dns_containers

        for container_id in offline_containers:
            delete_container(container_id, docker_client, dns_client,
                             container_wrapper)

        for container_id in new_containers:
            add_container(container_id, docker_client, dns_client,
                          container_wrapper)

        dns_containers = set(dns_client.containers)

        for container_id in dns_containers:
            container = get_container(container_id, docker_client,
                                      container_wrapper)
            if (not container or
                    not container.running or
                    not container.should_create_records):
                delete_container(container_id, docker_client, dns_client,
                                 container_wrapper)

        time.sleep(beat_interval)


def monitor_docker(docker_client, dns_client, container_wrapper):
    for event in docker_client.events():
        if event[STATUS] not in (START, DIE):
            continue

        container_id = event[ID][:10]

        if event[STATUS] == START:
            add_container(container_id, docker_client, dns_client,
                          container_wrapper)

        elif event[STATUS] == DIE:
            delete_container(container_id, docker_client, dns_client,
                             container_wrapper)

        time.sleep(0)


def monitor(docker_client, dns_client, container_wrapper, pool):
    def restart(gt, func, *args, **kwargs):
        try:
            gt.wait()
        except:
            LOG.exception('Exception in %s' % func.__name__)

        new_gt = pool.spawn(func, *args, **kwargs)
        new_gt.link(restart, func, *args, **kwargs)
        return new_gt

    dns_thread = pool.spawn(monitor_docker, docker_client, dns_client,
                            container_wrapper)
    docker_thread = pool.spawn(monitor_dns, docker_client, dns_client,
                               container_wrapper)

    dns_thread.link(restart, monitor_dns, docker_client, dns_client,
                    container_wrapper)
    docker_thread.link(restart, monitor_docker, docker_client, dns_client,
                       container_wrapper)


def main():
    desc = ('Monitor the docker event stream and create A records for '
            'containers')
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-n', '--nameserver', required=True,
                        help='nameserver to update/query')

    parser.add_argument('-o', '--origin', required=True,
                        help='origin domain to update')

    parser.add_argument('-k', '--tsig-key', default='/data/tsig.key',
                        help='path of tsig key file')

    parser.add_argument('-i', '--identity',
                        help='identity of this groundcontrol instance')

    parser.add_argument('-t', '--ttl', type=int, default=30,
                        help='ttl for records')

    parser.add_argument('--env-ip', default='DNS_IP',
                        help='environment key for ip override. '
                             'Default: DNS_IP')

    parser.add_argument('--env-name', default='DNS_NAME',
                        help='environment key for name override. '
                             'Default: DNS_NAME')

    parser.add_argument('--env-service', default='DNS_SERVICE',
                        help='environment key for name override. '
                             'Default: DNS_SERVICE')

    parser.add_argument('--env-skip', default='DNS_SKIP',
                        help='environment key to skip creation. '
                             'Default: DNS_SKIP')

    parser.add_argument('--update-timeout',
                        help='timeout for record updates')

    parser.add_argument('--resolver-timeout',
                        help='timeout for record checks')

    parser.add_argument('-q', '--quiet', action='store_true',
                        default=False,
                        help='disable logging output')

    parser.add_argument('-d', '--docker-url', default='unix://docker.sock',
                        help='http/unix url/socket to docker.')

    parser.add_argument('--skip-image', action='append',
                        help=('skip adding records for containers built from '
                              'image.'))

    parser.add_argument('--skip-service', action='append',
                        help=('skip adding records for containers of this '
                              'service.'))

    args = parser.parse_args()

    if not args.quiet:
        logging.basicConfig(format='%(message)s', level=logging.INFO)

    docker_client = docker.Client(base_url=args.docker_url)

    identity = args.identity

    if not identity:
        info = docker_client.inspect_container(os.environ['HOSTNAME'])
        identity = info[NAME].strip('/')

    resolver_timeout = None
    update_timeout = None

    if args.resolver_timeout is not None:
        resolver_timeout = float(args.resolver_timeout)

    if args.update_timout is not None:
        update_timeout = float(args.update_timeout)

    dns_client = DNS(identity=identity,
                     nameserver=args.nameserver,
                     origin=args.origin,
                     resolver_timeout=resolver_timeout,
                     tsig_key_path=args.tsig_key,
                     ttl=args.ttl,
                     update_timeout=update_timeout)

    env_ip_key = intern(args.env_ip)
    env_name_key = intern(args.env_name)
    env_service_key = intern(args.env_service)
    env_skip_key = intern(args.env_skip)

    container_wrapper = functools.partial(Container,
                                          env_ip_key=env_ip_key,
                                          env_name_key=env_name_key,
                                          env_service_key=env_service_key,
                                          env_skip_key=env_skip_key,
                                          skip_images=args.skip_image,
                                          skip_services=args.skip_service)

    pool = eventlet.GreenPool()
    monitor(docker_client, dns_client, container_wrapper, pool)
    pool.waitall()

if __name__ == '__main__':
    main()
