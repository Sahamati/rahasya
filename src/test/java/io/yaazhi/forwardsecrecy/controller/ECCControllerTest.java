package io.yaazhi.forwardsecrecy.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import io.yaazhi.forwardsecrecy.dto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;


@SpringBootTest
class ECCControllerTest {

    @Autowired
    ECCController eccController;

    @BeforeAll
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider()); 
    }
    
    @Test
     public void testFullFunction(){
        //Generate your key pair
        SerializedKeyPair ourSerializedKeyPair = eccController.generateKey();
        //No error
        assertNull(ourSerializedKeyPair.getErrorInfo());
        assertNotNull(ourSerializedKeyPair.getPrivateKey());

        //Generate remote key pair
        SerializedKeyPair remoteSerializedKeyPair = eccController.generateKey();
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
        CipherParameter encryptCipherParam = new CipherParameter();
        encryptCipherParam.setBase64Data(base64Data);
        encryptCipherParam.setBase64RemoteNonce(Base64.getEncoder().encodeToString(remoteNonce));
        encryptCipherParam.setBase64YourNonce(Base64.getEncoder().encodeToString(ourNonce));
        encryptCipherParam.setOurPrivateKey(ourSerializedKeyPair.getPrivateKey());
        encryptCipherParam.setRemoteKeyMaterial(remoteSerializedKeyPair.getKeyMaterial());
        CipherResponse encryptedCipherResponse = eccController.encrypt(encryptCipherParam);
        
        //Remote Decryption
        
        CipherParameter decryptCipherParam = new CipherParameter();
        decryptCipherParam.setBase64Data(encryptedCipherResponse.getBase64Data());
        decryptCipherParam.setBase64RemoteNonce(Base64.getEncoder().encodeToString(ourNonce));
        decryptCipherParam.setBase64YourNonce(Base64.getEncoder().encodeToString(remoteNonce));
        decryptCipherParam.setOurPrivateKey(remoteSerializedKeyPair.getPrivateKey());
        decryptCipherParam.setRemoteKeyMaterial(ourSerializedKeyPair.getKeyMaterial());
        
        CipherResponse decryptedCipherResponse = eccController.decrypt(decryptCipherParam);
        //System.out.println(decryptedCipherResponse.getBase64Data());
        assertEquals(base64Data, new String(Base64.getDecoder().decode(decryptedCipherResponse.getBase64Data())), "Encrypted and Decrypted Successfully");

    } 

    @Test
    public void testValidateTheSecretKeyGeneratedOnClientAndServerIsSimilar()  {
        //Generate server key pair
        final SerializedKeyPair serverKeyPair = eccController.generateKey();
        String serverPublicKey = serverKeyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
        String serverPrivateKey = serverKeyPair.getPrivateKey();

        //Generate remote key pair
        final SerializedKeyPair clientKeyPair = eccController.generateKey();
        String clientPublicKey = clientKeyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
        String clientPrivateKey = clientKeyPair.getPrivateKey();

        //Happening on Server
        SecretKeySpec spec = new SecretKeySpec(clientPublicKey, serverPrivateKey);
        SerializedSecretKey serverSideKey = eccController.getSharedKey(spec);
        System.out.println("The key that is generated on server side is ["+serverSideKey.getKey());

        //Happening on Client
        SecretKeySpec mobileSpec = new SecretKeySpec(serverPublicKey, clientPrivateKey);
        SerializedSecretKey clientSideKey = eccController.getSharedKey(mobileSpec);
        System.out.println("The key that is generated on client side is ["+clientSideKey.getKey());

        Assertions.assertEquals(serverSideKey.getKey(),clientSideKey.getKey());
    }
}