FROM registry.centos.org/centos/centos:7

LABEL name="f8analytics backbone services" \
      description="Stack aggregation and recommendation service." \
      git-sha="46e443d" \
      email-ids="nshaikh@redhat.com,samuzzal@redhat.com" \
      git-url="https://github.com/fabric8-analytics/f8a-server-backbone" \
      git-path="/" \
      target-file="Dockerfile" \
      app-license="GPL-3.0"

RUN yum install -y epel-release &&\
    yum install -y gcc git python36-pip python36-requests httpd httpd-devel python36-devel &&\
    yum clean all

COPY ./requirements.txt /

RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt && rm requirements.txt

COPY ./src /src

ADD scripts/entrypoint.sh /bin/entrypoint.sh

RUN chmod +x /bin/entrypoint.sh

ENTRYPOINT ["/bin/entrypoint.sh"]
