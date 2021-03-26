package io.yaazhi.forwardsecrecy.service;

import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;
import java.util.logging.Level;

@Log
@Service
public class XExchangeService {
    
    final String algorithm = "X25519";
    
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