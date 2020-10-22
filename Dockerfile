FROM registry.centos.org/centos/centos:7

ENV F8A_WORKER_VERSION=fefc764 \
    F8A_UTIL_VERSION=24f8858
LABEL name="f8analytics backbone services" \
      description="Stack aggregation and recommendation service." \
      git-sha="46e443d" \
      email-ids="yzainee@redhat.com,deepshar@redhat.com" \
      git-url="https://github.com/fabric8-analytics/f8a-server-backbone" \
      git-path="/" \
      target-file="Dockerfile" \
      app-license="GPL-3.0"

RUN yum install -y epel-release &&\
    yum install -y gcc git python36-pip python36-devel &&\
    yum clean all

COPY ./requirements.txt /

RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt && rm requirements.txt
RUN pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@${F8A_WORKER_VERSION}
RUN pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-utils.git@${F8A_UTIL_VERSION}
RUN pip3 install git+https://git@github.com/fabric8-analytics/fabric8-analytics-version-comparator.git#egg=f8a_version_comparator

COPY ./src /src

ADD scripts/entrypoint.sh /bin/entrypoint.sh

RUN chmod +x /bin/entrypoint.sh

ENTRYPOINT ["/bin/entrypoint.sh"]
