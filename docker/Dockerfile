ARG TOMCAT_VERSION=8.5
ARG TOMCAT_JRE=jre8

FROM maven:3-jdk-8 AS builder

ARG BUILD_PROFILE

ENV \
    BUILD_DIR=/tmp/guacamole-docker-BUILD

RUN apt-get update && apt-get install -y git

RUN git clone --single-branch --branch staging/1.2.0 https://github.com/apache/guacamole-client.git /tmp/guacclient/ && \
    mkdir -p "$BUILD_DIR" && \
    mkdir -p /opt/guacamole/bin/ && \
    cp -r /tmp/guacclient/guacamole-docker/bin/* /opt/guacamole/bin/ && \
    mv /tmp/guacclient/* "$BUILD_DIR" && \
    apt-get remove -y git && \
    rm -rf /var/lib/apt/lists/*

RUN /opt/guacamole/bin/build-guacamole.sh "$BUILD_DIR" /opt/guacamole "$BUILD_PROFILE"

FROM tomcat:${TOMCAT_VERSION}-${TOMCAT_JRE}

WORKDIR /opt/guacamole

COPY --from=builder /opt/guacamole/ .

EXPOSE 8443

COPY guacamole-auth-cognito-*-all.jar /etc/guacamole/extensions/
COPY guac-manifest.json /etc/guacamole/extensions/
COPY entrypoint.sh /entrypoint.sh
COPY start.sh /opt/guacamole/bin/start.sh
COPY context.xml /usr/local/tomcat/conf/
COPY server.xml /usr/local/tomcat/conf/
COPY rewrite.config /usr/local/tomcat/webapps/ROOT/WEB-INF/

RUN  chmod 755 /opt/guacamole/bin/start.sh
RUN  chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
