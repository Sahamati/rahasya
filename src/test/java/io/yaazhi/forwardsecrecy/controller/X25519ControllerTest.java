package io.yaazhi.forwardsecrecy.controller;

import io.yaazhi.forwardsecrecy.dto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
class X25519ControllerTest {

    @Autowired
    X25519Controller x25519Controller;

    @BeforeAll
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider()); 
    }

    @Test
    public void testFullFunction() {
        //Generate your key pair
        SerializedKeyPair ourSerializedKeyPair = x25519Controller.generateKey();
        //No error
        assertNull(ourSerializedKeyPair.getErrorInfo());
        assertNotNull(ourSerializedKeyPair.getPrivateKey());

        //Generate remote key pair
        SerializedKeyPair remoteSerializedKeyPair = x25519Controller.generateKey();
        //No error
        assertNull(remoteSerializedKeyPair.getErrorInfo());
        assertNotNull(remoteSerializedKeyPair.getPrivateKey());


        //   String base64Data = "TGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4g";
        String base64Data = "Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. Let us test to ensure we are all doing a good job. Hope its all true that we are doing good. ";
        SecureRandom sr = new SecureRandom();
        byte ourNonce[] = new byte[32];
        byte remoteNonce[] = new byte[32];

        //Your Encryption
        sr.nextBytes(ourNonce);
        sr.nextBytes(remoteNonce);
        EncryptCipherParameter encryptCipherParam = new EncryptCipherParameter();
        encryptCipherParam.setData(base64Data);
        encryptCipherParam.setBase64RemoteNonce(Base64.getEncoder().encodeToString(remoteNonce));
        encryptCipherParam.setBase64YourNonce(Base64.getEncoder().encodeToString(ourNonce));
        encryptCipherParam.setOurPrivateKey(ourSerializedKeyPair.getPrivateKey());
        encryptCipherParam.setRemoteKeyMaterial(remoteSerializedKeyPair.getKeyMaterial());
        CipherResponse encryptedCipherResponse = x25519Controller.encrypt(encryptCipherParam);

        //Remote Decryption

        DecryptCipherParameter decryptCipherParam = new DecryptCipherParameter();
        decryptCipherParam.setBase64Data(encryptedCipherResponse.getBase64Data());
        decryptCipherParam.setBase64RemoteNonce(Base64.getEncoder().encodeToString(ourNonce));
        decryptCipherParam.setBase64YourNonce(Base64.getEncoder().encodeToString(remoteNonce));
        decryptCipherParam.setOurPrivateKey(remoteSerializedKeyPair.getPrivateKey());
        decryptCipherParam.setRemoteKeyMaterial(ourSerializedKeyPair.getKeyMaterial());

        CipherResponse decryptedCipherResponse = x25519Controller.decrypt(decryptCipherParam);
        //System.out.println(decryptedCipherResponse.getBase64Data());
        assertEquals(base64Data, new String(Base64.getDecoder().decode(decryptedCipherResponse.getBase64Data())), "Encrypted and Decrypted Successfully");

    }

    @Test
    public void testValidateTheSecretKeyGeneratedOnClientAndServerIsSimilar()  {
        //Generate server key pair
        final SerializedKeyPair serverKeyPair = x25519Controller.generateKey();
        String serverPublicKey = serverKeyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
        String serverPrivateKey = serverKeyPair.getPrivateKey();

        //Generate remote key pair
        final SerializedKeyPair clientKeyPair = x25519Controller.generateKey();
        String clientPublicKey = clientKeyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
        String clientPrivateKey = clientKeyPair.getPrivateKey();

        //Happening on Server
        SecretKeySpec spec = new SecretKeySpec(clientPublicKey, serverPrivateKey);
        SerializedSecretKey serverSideKey = x25519Controller.getSharedKey(spec);
        System.out.println("The key that is generated on server side is ["+serverSideKey.getKey());

        //Happening on Client
        SecretKeySpec mobileSpec = new SecretKeySpec(serverPublicKey, clientPrivateKey);
        SerializedSecretKey clientSideKey = x25519Controller.getSharedKey(mobileSpec);
        System.out.println("The key that is generated on client side is ["+clientSideKey.getKey());

        Assertions.assertEquals(serverSideKey.getKey(),clientSideKey.getKey());
    }


}