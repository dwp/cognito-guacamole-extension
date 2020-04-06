FROM guacamole/guacamole:1.1.0
COPY guacamole-auth-cognito-*-all.jar /etc/guacamole/extensions/
COPY guac-manifest.json /etc/guacamole/extensions/
COPY start.sh /opt/guacamole/bin/start.sh
RUN  chmod 755 /opt/guacamole/bin/start.sh
