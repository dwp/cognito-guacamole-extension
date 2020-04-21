FROM guacamole/guacamole:1.1.0
COPY guacamole-auth-cognito-*-all.jar /etc/guacamole/extensions/
COPY guac-manifest.json /etc/guacamole/extensions/
COPY start.sh /opt/guacamole/bin/start.sh
COPY context.xml /usr/local/tomcat/conf/
COPY rewrite.config /usr/local/tomcat/webapps/ROOT/WEB-INF/
RUN  chmod 755 /opt/guacamole/bin/start.sh
