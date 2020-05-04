#!/usr/bin/env bash

/usr/bin/openssl req -x509 -newkey rsa:4096 -keyout /usr/local/tomcat/conf/key.pem -out /usr/local/tomcat/conf/cert.pem -days 3650 -nodes -subj '/CN=guacamole'

/opt/guacamole/bin/start.sh $@