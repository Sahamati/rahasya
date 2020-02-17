package io.yaazhi.forwardsecrecy.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.yaazhi.forwardsecrecy.controller.ECCController;
import io.yaazhi.forwardsecrecy.dto.CipherParameter;
import io.yaazhi.forwardsecrecy.dto.CipherResponse;
import io.yaazhi.forwardsecrecy.dto.SerializedKeyPair;

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

        
        String base64Data = "TGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4gTGV0IHVzIHRlc3QgdG8gZW5zdXJlIHdlIGFyZSBhbGwgZG9pbmcgYSBnb29kIGpvYi4gSG9wZSBpdHMgYWxsIHRydWUgdGhhdCB3ZSBhcmUgZG9pbmcgZ29vZC4g";
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
        encryptCipherParam.setRemoteKeyMaterial(remoteSerializedKeyPair.getKeyMaterials());
        CipherResponse encryptedCipherResponse = eccController.encrypt(encryptCipherParam);
        
        //Remote Decryption
        
        CipherParameter decryptCipherParam = new CipherParameter();
        decryptCipherParam.setBase64Data(encryptedCipherResponse.getBase64Data());
        decryptCipherParam.setBase64RemoteNonce(Base64.getEncoder().encodeToString(ourNonce));
        decryptCipherParam.setBase64YourNonce(Base64.getEncoder().encodeToString(remoteNonce));
        decryptCipherParam.setOurPrivateKey(remoteSerializedKeyPair.getPrivateKey());
        decryptCipherParam.setRemoteKeyMaterial(ourSerializedKeyPair.getKeyMaterials());
        
        CipherResponse decryptedCipherResponse = eccController.decrypt(decryptCipherParam);
        assertEquals(base64Data, decryptedCipherResponse.getBase64Data(), "Encrypted and Decrypted Succesfully");

    }

}