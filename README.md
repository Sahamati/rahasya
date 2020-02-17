# Forwardsecrecy

The project aims to simplyfy the usage of ECC curve (curve25519) with Diffie-Hellman Key exchange.  
The work is inline with the Account Agregator Specification.

## How to Run
The image is pushed into docker hub. Thats the easiest to start
https://hub.docker.com/r/gsasikumar/forwardsecrecy/tags

1. docker pull gsasikumar/forwardsecrecy:v1
2. docker run -p 8080:8080 gsasikumar/forwardsecrecy:v1
3. Access the swagger as localhost port 8080. http://localhost:8080/swagger-ui.html


## How to build
1. ./gradlew build
2. docker build -t gsasikumar/forwardsecrecy:v1.1 .

## How to run docker
1. docker run -p 8080:8080 gsasikumar/forwardsecrecy:v1.1

