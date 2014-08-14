FROM crosbymichael/python

RUN apt-get update && \
    apt-get install -y \
        python-eventlet \
        python-dnspython

RUN pip install docker-py

ADD groundcontrol.py /groundcontrol.py

ENTRYPOINT ["/groundcontrol.py"]
