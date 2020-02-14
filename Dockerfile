FROM openjdk:8-jdk-alpine
LABEL maintainer="gsasikumar@github"

EXPOSE 8080
ADD build/libs/forwardsecrecy-0.0.1-SNAPSHOT.jar forwardsecrecy.jar
ADD build/libs/bcprov-jdk15on-1.64.jar bcprov-jdk15on-1.64.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom", "-cp", "/bcprov-jdk15on-1.64.jar","-jar","/forwardsecrecy.jar"]