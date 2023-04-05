package rahasya_ecdh_encryption;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.KeyAgreement;

public class DHEService{
    
    final String algorithm = "ECDH";
    final String provider = "BC" ;

        public  DHEService () {
            
        }
        
        public String getSharedSecret(PrivateKey ourPrivatekey, PublicKey remotePublicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
            KeyAgreement ecdhKeyAgreement = KeyAgreement.getInstance(algorithm, provider);
            ecdhKeyAgreement.init(ourPrivatekey);
            ecdhKeyAgreement.doPhase(remotePublicKey,true);
            final byte[] secretKey = ecdhKeyAgreement.generateSecret();
            return Base64.getEncoder().encodeToString(secretKey);
        }

}