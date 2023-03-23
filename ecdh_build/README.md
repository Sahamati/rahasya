# Introduction

This readme will guide about rahasya_ecdh_encryption JAR file.
This jar file is created using code available in this report.
It is meant to serve as infrastructure for any entity looking to implement 
encryption, which FIPs are required to do as per REBIT/Sahmati standards.
It can also be used as reference by FIUs, and AAs to check their respective encryption and decryption algorithms. The code used for this JAR is already available in the same repo.
The jar file in this folder is generated using BouncyCastle Library as well as java code in this repo.
However, BouncyCastle library is required for the execution of this code

## Sample Usage

### Compiling test file

```bash
cd rahasya/ecdh_build/build_src
javac -cp ".;../lib/rahasya_ecdh_encryption.jar"  test/Main.java
```

### Adding BouncyCastle provider

[Steps to add BouncyCastle library](https://tomee.apache.org/bouncy-castle.html)

### Running the test file

```bash
java -cp ".;../lib/rahasya_ecdh_encryption.jar;../lib/bcprov-jdk15on-1.70.jar"  test/Main
```
