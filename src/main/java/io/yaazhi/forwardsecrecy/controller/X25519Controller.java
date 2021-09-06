package io.yaazhi.forwardsecrecy.controller;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.yaazhi.forwardsecrecy.dto.*;
import io.yaazhi.forwardsecrecy.service.X25519Service;
import io.yaazhi.forwardsecrecy.service.XCipherService;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

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


@Log
@RestController
@RequestMapping("/x25519/v1")
public class X25519Controller {

    @Autowired
    private X25519Service x25519Service;

    @Autowired
    private XCipherService cipherService;

    @ApiOperation(value = "Generate a new ecc key pair")
    @GetMapping(value="/generateKey", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully created"),
			@ApiResponse(code = 400, message = " Request body passed  is null or invalid"),
			@ApiResponse(code = 500, message = " Error occurred") })
    public SerializedKeyPair generateKey() {
        try {
            log.info("Generate Key");
            return x25519Service.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException ex){
            log.log(Level.SEVERE, "Unable to generateKey");
            final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    @ApiOperation(value = "Generate the shared key for the given remote public key (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format). The keys can also be in plain hex encoded as in lib sodium. The api will auto detect the same")
    @PostMapping(value = "/getSharedKey", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully derived the key"),
            @ApiResponse(code = 500, message = " error occurred while deriving secret key") })
    public SerializedSecretKey getSharedKey(@RequestBody final SecretKeySpec spec) {
        try {
            log.info("Generate Shared Secret");
            final String secretKey = x25519Service.getSharedSecret(spec.getOurPrivateKey(), spec.getRemotePublicKey());
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | InvalidKeySpecException ex) {
            log.log(Level.SEVERE, "Error when deriving secret key");
            final SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    @ApiOperation(value = "Encrypt the data for the given key material (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) , remote nonce (base64) and local nonce (base64). Send the input data as a string. Encryption assumes the given data is a string")
    @PostMapping(value = "/encrypt", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully encrypted the data"),
			@ApiResponse(code = 500, message = " error occurred while encrypting the given data") })
    public CipherResponse encrypt(@RequestBody final EncryptCipherParameter encryptCipherParam) {
        try {
            log.info("Encrypt complete data");
            log.log(Level.FINE, "Get PrivateKey");
            final Key ourPrivateKey = x25519Service.getPEMDecodedStream(encryptCipherParam.getOurPrivateKey(), true);
            log.log(Level.FINE, "Get PublicKey");
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
            log.log(Level.FINE, "Initiate Encryption");
            String result= cipherService.encrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, encryptCipherParam.getBase64YourNonce(), encryptCipherParam.getBase64RemoteNonce(), encryptCipherParam.getData());
            log.log(Level.FINE, "Completed Encryption");
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException ex) {

            log.log(Level.SEVERE, "Error during encryption");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
    
    
    @ApiOperation(value = "Decrypt the data for the given remote public key (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) , remote nonce (base64) and local nonce (base64). The result is base64 encoded")
    @PostMapping(value = "/decrypt", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully encrypted the data"),
			@ApiResponse(code = 500, message = " error occurred while encrypting the given data") })
    public CipherResponse decrypt(@RequestBody final DecryptCipherParameter decryptCipherParam) {
        try {
            log.info("Decrypt complete data");
            log.log(Level.FINE, "Get PrivateKey");
            final Key ourPrivateKey = x25519Service.getPEMDecodedStream(decryptCipherParam.getOurPrivateKey(), true);
            log.log(Level.FINE, "Get PublicKey");
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
            log.log(Level.FINE, "Initiate Decryption");
            String result= cipherService.decrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, decryptCipherParam.getBase64YourNonce(), decryptCipherParam.getBase64RemoteNonce(), decryptCipherParam.getBase64Data());
            log.log(Level.FINE, "Completed Decryption");
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | IOException ex) {

            log.log(Level.SEVERE, "Error during decryption");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
    
}