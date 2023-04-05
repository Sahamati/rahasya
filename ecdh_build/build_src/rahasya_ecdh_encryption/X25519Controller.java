package rahasya_ecdh_encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.Map;
import java.util.HashMap;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;
import java.util.Calendar;
import java.util.Base64;
import java.util.TimeZone;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class X25519Controller {

    private X25519Service x25519Service;
    private XCipherService cipherService;
    

    public X25519Controller () {

        this.x25519Service = new X25519Service();
        this.cipherService = new XCipherService ();
    }


    public SerializedKeyPair generateKey() {
        try {
            return x25519Service.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException ex){
            final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    public SerializedSecretKey getSharedKey(final SecretKeySpec spec) {
        try {

            final String secretKey = x25519Service.getSharedSecret(spec.getOurPrivateKey(), spec.getRemotePublicKey());
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | InvalidKeySpecException ex) {

            final SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    public CipherResponse encrypt(final EncryptCipherParameter encryptCipherParam) {
        
        try {
            final Key ourPrivateKey = x25519Service.getPEMDecodedStream(encryptCipherParam.getOurPrivateKey(), true);
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no 
            Date expiryDate;
            
            try {
                expiryDate = df.parse(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
            }
            catch(ParseException ex){
                throw new InvalidKeyException("Unable to parse date");
            }
            
            if (!expiryDate.after(new Date())){
                throw new InvalidKeyException("Expired Key");
            }
            final Key ourPublicKey = x25519Service.getPEMDecodedStream(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue(), false);
            String result= cipherService.encrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, encryptCipherParam.getBase64YourNonce(), encryptCipherParam.getBase64RemoteNonce(), encryptCipherParam.getData());
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException ex) {

          //  log.log(Level.SEVERE, "Error during encryption");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
    
   
    public CipherResponse decrypt( final DecryptCipherParameter decryptCipherParam) {
        try {
            final Key ourPrivateKey = x25519Service.getPEMDecodedStream(decryptCipherParam.getOurPrivateKey(), true);
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no 
            Date expiryDate;
            try {
                expiryDate = df.parse(decryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
            }
            catch(ParseException ex){
                throw new InvalidKeyException("Unable to parse date");
            }
            
            if (!expiryDate.after(new Date())){
                throw new InvalidKeyException("Expired Key");
            }
            final Key ourPublicKey = x25519Service.getPEMDecodedStream(decryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue(), false);
            String result= cipherService.decrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, decryptCipherParam.getBase64YourNonce(), decryptCipherParam.getBase64RemoteNonce(), decryptCipherParam.getBase64Data());
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException ex) {

            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
}