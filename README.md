# Rahasya [![Codacy Badge](https://app.codacy.com/project/badge/Grade/8d51e12ebfff45c1a212af0f38aaa0cc)](https://www.codacy.com/gh/Sahamati/rahasya/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Sahamati/rahasya&amp;utm_campaign=Badge_Grade)

The project aims to simplify the usage of ECC curve (curve25519) with Diffie-Hellman Key exchange.  
The work is inline with the Account Aggregator Specification.

__NOTE__: This project is moved from gsasikumar/forwardsecrecy as on 25/08/2021

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

