package io.yaazhi.forwardsecrecy.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.KeyAgreement;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.logging.Level;
import lombok.extern.java.Log;

@Log
@Service
public class DHEService{
    
    final String algorithm = "ECDH";
    
    @Value("${forwardsecrecy.dhe.provider:BC}")
    String provider;    
        
        public String getSharedSecret(PrivateKey ourPrivatekey, PublicKey remotePublicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
            KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance(algorithm, provider);
            ecdhKeyAgreement.init(ourPrivatekey);
            ecdhKeyAgreement.doPhase(remotePublicKey,true);
            final byte[] secretKey = ecdhKeyAgreement.generateSecret();
            log.log(Level.FINE, "Created the secret key");
            return Base64.getEncoder().encodeToString(secretKey);
        }

}