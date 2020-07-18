# Forwardsecrecy

The project aims to simplify the usage of ECC curve (curve25519) with Diffie-Hellman Key exchange.  
The work is inline with the Account Aggregator Specification.

## How to Run
The image is pushed into docker hub. Thats the easiest to start
https://hub.docker.com/r/gsasikumar/forwardsecrecy/tags

1. docker pull gsasikumar/forwardsecrecy:V1.2
2. docker run -p 8080:8080 gsasikumar/forwardsecrecy:V1.2
3. Access the swagger as localhost port 8080. http://localhost:8080/swagger-ui.html


## How to build
1. ./gradlew build

## How to run docker
1. docker run -p 8080:8080 gsasikumar/forwardsecrecy:V1.2

