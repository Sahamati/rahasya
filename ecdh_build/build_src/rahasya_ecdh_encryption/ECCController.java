package rahasya_ecdh_encryption;

import java.util.Date;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class ECCController {

    private ECCService eccService = new ECCService ();
    private DHEService dheService = new DHEService();
    private CipherService cipherService = new CipherService();

    public SerializedKeyPair generateKey() {
        try {

            return eccService.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex){
            final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    public SerializedSecretKey getSharedKey( final SecretKeySpec spec) {
        try {
            final Key ourPrivateKey = eccService.getPEMDecodedStream(spec.getOurPrivateKey());
            final Key ourPublicKey = eccService.getPEMDecodedStream(spec.getRemotePublicKey());
            final String secretKey = dheService.getSharedSecret((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey);
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException ex) {
            final SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    public CipherResponse encrypt( final EncryptCipherParameter encryptCipherParam) {
        try {
            final Key ourPrivateKey = eccService.getPEMDecodedStream(encryptCipherParam.getOurPrivateKey());
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
            final Key ourPublicKey = eccService.getPEMDecodedStream(encryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
            String result= cipherService.encrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, encryptCipherParam.getBase64YourNonce(), encryptCipherParam.getBase64RemoteNonce(), encryptCipherParam.getData());
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException  ex) {

            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
    
    
    public CipherResponse decrypt( final DecryptCipherParameter decryptCipherParam) {
        try {

            final Key ourPrivateKey = eccService.getPEMDecodedStream(decryptCipherParam.getOurPrivateKey());
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
            final Key ourPublicKey = eccService.getPEMDecodedStream(decryptCipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
            String result= cipherService.decrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, decryptCipherParam.getBase64YourNonce(), decryptCipherParam.getBase64RemoteNonce(), decryptCipherParam.getBase64Data());
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {

            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
}