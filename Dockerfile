FROM python:3.10.7-alpine3.16

LABEL maintainer="Informatica Interna <sysinternal@stratio.com>"
LABEL name="remove-external-users-expired" \
        version="0.1" \
        description="Remove expired external users" \
        vendor="Stratio" \
        license="Stratio license"

# Install requisites
RUN mkdir /external-users

COPY config.ini /external-users/
COPY main.py /external-users/
COPY requirements.txt /external-users/
COPY entrypoint.sh /

RUN adduser -D -H -h /external-users stratio
RUN chown -R stratio:stratio /external-users
RUN chown -R stratio:stratio /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER stratio
WORKDIR /external-users
RUN pip3 install -r /external-users/requirements.txt


ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
