FROM azul/zulu-openjdk-alpine:11 as packager
LABEL maintainer="gsasikumar@github"

RUN { \
        java --version ; \
        echo "jlink version:" && \
        /usr/lib/jvm/zulu11/bin/jlink --version ; \
    }
ENV JAVA_MINIMAL=/opt/jre
# build modules distribution
RUN /usr/lib/jvm/zulu11/bin/jlink \
    --verbose \
    --add-modules \
        java.base,java.sql,java.naming,java.desktop,java.management,java.security.jgss,java.instrument \
        # java.naming - javax/naming/NamingException
        # java.desktop - java/beans/PropertyEditorSupport
        # java.management - javax/management/MBeanServer
        # java.security.jgss - org/ietf/jgss/GSSException
        # java.instrument - java/lang/instrument/IllegalClassFormatException
    --compress 2 \
    --strip-debug \
    --no-header-files \
    --no-man-pages \
    --output "$JAVA_MINIMAL"
# Second stage, add only our minimal "JRE" distr and our app
FROM alpine
ENV JAVA_MINIMAL=/opt/jre
ENV PATH="$PATH:$JAVA_MINIMAL/bin"
COPY --from=packager "$JAVA_MINIMAL" "$JAVA_MINIMAL"

EXPOSE 8080
ADD ./build/libs/forwardsecrecy.jar forwardsecrecy.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom", "-jar","/forwardsecrecy.jar"]
