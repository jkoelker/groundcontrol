FROM crosbymichael/python

RUN apt-get update && \
    apt-get install -y \
        python-eventlet \
        python-dnspython \
        python-docker

ADD groundcontrol.py /groundcontrol.py

ENTRYPOINT ["/groundcontrol.py"]
