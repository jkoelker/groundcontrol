Groundcontrol
=============
Automatic Dynamic DNS Updates for [Docker](https://github.com/dotcloud/docker)


NOTE
----

Before using Groundcontrol, you should investigate
[SkyDNS](https://github.com/skynetservices/skydns) and
[Skydock](https://github.com/crosbymichael/skydock) to determine if your use
case is better served by those projects.


The Deets
---------

Groundcontol listens to the Docker event stream and uses Dynamic DNS Updates
to modify an existing zone. It allows gradually adding Docker hosted application
to your existing DNS infrastucture.


Installation
------------

While not strictly necessary, Groundcontrol is meant to be run in a container
on the Docker host it is managing records for. After installing and
configuring Docker to your liking pull the image from the Docker index:


```bash
docker pull jkoelker/groundcontrol
```

Ground control requires access to a TSIG key to sign Dynamic DNS Update
requests. By default it will look for this file in `/data/tsig.key`. Generate
a key using `dnssec-keygen`:

```bash
dnssec-keygen -a HMAC-MD5 -b 128 -r /dev/urandom -n USER DDNS_UPDATE
```
This generates a `.key` and a `.private` file. Read the
[manpage](http://linux.die.net/man/8/dnssec-keygen) to find out more. `cat`
out the `.key` file, it should look like:

```bash
DDNS_UPDATE. IN KEY 0 3 157 lVyOSdkNGXY8768NGoBxrA==
```

The last column is the key's secret. Edit your `named.conf` and add the key:

```bash
key DDNS_UPDATE {
    algorithm HMAC-MD5.SIG-ALG.REG.INT;
    secret "lVyOSdkNGXY8768NGoBxrA==";
};
```

**WARNING** Make sure to use your own generated secret. Failure to do so will
Allow anyone with the above secret to edit your zone file.

Then specify the key in the `allow-update` field of the zone definition:

```bash
zone "example.com" {
    type master;
    allow-update { key DDNS_UPDATE; };
    file "example.com";
};
```

Reload your bind configuration in the usual manner (e.g. `rndc reload`).
Now create a Volume container to house the key (make sure to
`docker pull busybox` if you don't have it already):

```bash
docker run -d -v /data --name tsig-volume busybox true
```

Then run a container to add the key into the volume:

```bash
docker run -t -i --volumes-from tsig-volume --name temp-tsig busybox /bin/sh -l
echo "DDNS_UPDATE. IN KEY 0 3 157 lVyOSdkNGXY8768NGoBxrA==" > /data/tsig.key
exit
```

At this point you can clean up this temporary container:

```bash
docker rm -v temp-tsig
```

Finnaly run the Groundcontrol container:

```bash
docker run -d -e 'DNS_SKIP=true' --volumes-from tsig-volume -v /var/run/docker.sock:/docker.sock --name groundcontrol jkoelker/groundcontrol --nameserver <NAMESERVER_IP> --origin example.com
```

Ground control should now be running. You can verify by checking the logs:

```bash
docker logs groundcontrol
```

You should see the logging output like `Managing records in example.com.`. Try
booting a test container:

```bash
docker run -d -t --name test busybox /bin/sh
```

The following records should be created (if not, then make sure bind has write
access to the zone file location so it can create the dynamic zone file):

```bash
busybox.example.com.                  30      IN      A       172.16.10.3
groundcontrol.example.com.            30      IN      SRV     10 10 0 e133cca44d.groundcontrol.example.com.
e133cca44d.groundcontrol.example.com. 30      IN      CNAME   test.groundcontrol.example.com.
test.groundcontrol.example.com.       30      IN      A       172.16.10.3
test.groundcontrol.example.com.       30      IN      SRV     10 10 0 busybox.example.com.
```

The first record is the `A` record for this service. The service is determined
by the last part of the image when split on '/'. That is all containers
created using the image `example/www` will have an `A` record created for
`www.example.com`.

Groundcontrol (by default) will use its own container name as a record
store under the `<name>.example.com` hierarchy. If more than one Groundcontrol
instance is workin on a given zone, then you must ensure this is unique per
Groundcontrol instance, either by naming them differently or by forcing
the `identity` of the instance using the `-i` or `--identity` option to
Groundcontrol.

Every container will then get a `SRV` record at `groundcontrol.example.com.`
pointing to the container's short uuid. Currently the priority, weight, and
port fields are the static values '10 10 0' as these records are intended
for Groundcontrol's use.

A `CNAME` record is created for the container's uuid record to point to the
name `A` record for that container.

The final record is a `SRV` record for the container pointing to the service
it is participating in.


Usage
-----

```
usage: groundcontrol.py [-h] -n NAMESERVER -o ORIGIN [-k TSIG_KEY]
                        [-i IDENTITY] [-t TTL] [--env-ip ENV_IP]
                        [--env-name ENV_NAME] [--env-service ENV_SERVICE]
                        [--env-skip ENV_SKIP]
                        [--update-timeout UPDATE_TIMEOUT]
                        [--resolver-timeout RESOLVER_TIMEOUT] [-q]
                        [-d DOCKER_URL] [--skip-image SKIP_IMAGE]
                        [--skip-service SKIP_SERVICE]

Monitor the docker event stream and create A records for containers

optional arguments:
  -h, --help            show this help message and exit
  -n NAMESERVER, --nameserver NAMESERVER
                        nameserver to update/query
  -o ORIGIN, --origin ORIGIN
                        origin domain to update
  -k TSIG_KEY, --tsig-key TSIG_KEY
                        path of tsig key file
  -i IDENTITY, --identity IDENTITY
                        identity of this groundcontrol instance
  -t TTL, --ttl TTL     ttl for records
  --env-ip ENV_IP       environment key for ip override. Default: DNS_IP
  --env-name ENV_NAME   environment key for name override. Default: DNS_NAME
  --env-service ENV_SERVICE
                        environment key for name override. Default:
                        DNS_SERVICE
  --env-skip ENV_SKIP   environment key to skip creation. Default: DNS_SKIP
  --update-timeout UPDATE_TIMEOUT
                        timeout for record updates
  --resolver-timeout RESOLVER_TIMEOUT
                        timeout for record checks
  -q, --quiet           disable logging output
  -d DOCKER_URL, --docker-url DOCKER_URL
                        http/unix url/socket to docker.
  --skip-image SKIP_IMAGE
                        skip adding records for containers built from image.
  --skip-service SKIP_SERVICE
                        skip adding records for containers of this service.
```

Groundcontrol allows many ways to override or skip creation of records.
Earlier the Groundcontrol instance was started with the environment
variable `DNS_SKIP=true`. This environment variable (if set to anything
or existing at all) will prevent Groundcontrol from creating records for
that container.

The `--skip-image` and `--skip-service` options can be specified multiple
times to add an image (full image name) or service name to the exclusion list.
For example to skip record creation of all `busybox` containers, you can
specify `--skip-image busybox`.

Finally you can force a container's record values with the `DNS_IP`,
`DNS_NAME`, and `DNS_SERVICE` environment variabes when booting that
container. The `--env-ip`, `--env-name`, and `--env-service` options determine
what environment variables will be inspected, so you can override them if
needed.
