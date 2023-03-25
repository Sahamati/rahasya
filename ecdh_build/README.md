# Introduction

This readme will guide about rahasya_ecc25519_x25519 JAR file.
This jar file is created using code available in this report.
It can be used for ECC25519 as well as X25519 operations.
It is meant to serve as infrastructure for any entity looking to implement 
encryption, which FIPs are required to do as per REBIT/Sahmati standards.
It can also be used as reference by FIUs, and AAs to check their respective encryption and decryption algorithms. The code used for this JAR is already available in the same repo.
The jar file in this folder is generated using BouncyCastle Library as well as java code in this repo.
However, BouncyCastle library is required for the execution of this code

## Adding BouncyCastle provider

[Steps to add BouncyCastle library](https://tomee.apache.org/bouncy-castle.html)

## Sample Usage

### Compiling test file for X25519

```bash
cd rahasya/ecdh_build
javac -cp ".;lib/rahasya_ecc25519_x25519.jar"  TestX25519.java
```

### Running the test file for X25519

```bash
java -cp ".;lib/rahasya_ecc25519_x25519.jar;lib/bcprov-jdk15on-1.70.jar"  X25519Main
```

### Compiling test file for ECC25519

```bash
cd rahasya/ecdh_build
javac -cp ".;lib/rahasya_ecc25519_x25519.jar"  TestECC25519.java
```

### Running the test file for ECC25519

```bash
java -cp ".;lib/rahasya_ecc25519_x25519.jar;lib/bcprov-jdk15on-1.70.jar"  ECC25519Main
```
