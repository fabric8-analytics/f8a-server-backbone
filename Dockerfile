FROM registry.centos.org/centos/centos:7
ENV ENUM_FILE_COMMIT=5ce3c7fc23fa7b88e19a584b8b6f4af9e68adee4 \
    ERROR_FILE_COMMIT=9c33cad39581aa90b427a40c46af242f043c2c7c \
    DEFAULTS_FILE_COMMIT=e15ef1b1867a8d9208c897304d04441f4ae1e8a8 \
    MODELS_FILE_COMMIT=0f0cb832452e5ffb1971e38fcda08bc0a67d817b

RUN yum install -y epel-release &&\
    yum install -y gcc wget python34-pip python34-requests httpd httpd-devel python34-devel &&\
    yum clean all

COPY ./requirements.txt /

RUN pip3 install -r requirements.txt && rm requirements.txt

COPY ./src /src
RUN mkdir /src/f8a_worker
RUN wget -O /src/models.py https://raw.githubusercontent.com/fabric8-analytics/fabric8-analytics-worker/${MODELS_FILE_COMMIT}/f8a_worker/models.py
RUN wget -O /src/f8a_worker/errors.py https://raw.githubusercontent.com/fabric8-analytics/fabric8-analytics-worker/${MODELS_FILE_COMMIT}/f8a_worker/errors.py
RUN wget -O /src/f8a_worker/enums.py https://raw.githubusercontent.com/fabric8-analytics/fabric8-analytics-worker/${MODELS_FILE_COMMIT}/f8a_worker/enums.py
RUN wget -O /src/f8a_worker/defaults.py https://raw.githubusercontent.com/fabric8-analytics/fabric8-analytics-worker/${MODELS_FILE_COMMIT}/f8a_worker/defaults.py

ADD scripts/entrypoint.sh /bin/entrypoint.sh

RUN chmod 777 /bin/entrypoint.sh

ENTRYPOINT ["/bin/entrypoint.sh"]
