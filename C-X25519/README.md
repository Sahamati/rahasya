# Rahasya C library

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/8d51e12ebfff45c1a212af0f38aaa0cc)](https://www.codacy.com/gh/Sahamati/rahasya/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Sahamati/rahasya&amp;utm_campaign=Badge_Grade)

The project aims to simplify the usage of ECC curve (curve25519) with Diffie-Hellman Key exchange.  
The work is inline with the Account Aggregator Specification.

__NOTE__: This project is moved from gsasikumar/forwardsecrecy as on 25/08/2021

## Getting Involved / Contributing

To contribute, simply make a pull request and add a brief description of your addition or change. For
more details, check the [contribution guidelines](.github/CONTRIBUTING.md).

## Introduction
This project is created as a static library. So use the test method executable to run.

## How to build
Please ensure you are in the C-X25519 folder.
1. cmake -Bbuild . 
2. cd build && make && cd ..

## How to run(test)
Please ensure you are in the C-X25519 folder.
1. sh test.sh
2. ./x25519_test