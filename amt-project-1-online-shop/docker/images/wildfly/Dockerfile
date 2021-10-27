FROM jboss/wildfly:16.0.0.Final

USER root
RUN mkdir /db
RUN chown jboss:jboss /db

USER jboss

# copy sqlite driver
ADD docker/images/wildfly/sqlite-jdbc-3.28.0.jar /opt/jboss/wildfly/modules/system/layers/base/org/sqlite/main/
ADD docker/images/wildfly/module.xml             /opt/jboss/wildfly/modules/system/layers/base/org/sqlite/main/

# add user to access management console
RUN /opt/jboss/wildfly/bin/add-user.sh admin admin --silent

# copy and execute wildfly config script
COPY docker/images/wildfly/commands.cli /opt/jboss/wildfly/custom/
COPY docker/images/wildfly/config.sh    /opt/jboss/wildfly/custom/
RUN /opt/jboss/wildfly/custom/config.sh

# expose the management console and the app when wildfly starts
CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-DXmx4g", "-b", "0.0.0.0", "-bmanagement", "0.0.0.0"]
