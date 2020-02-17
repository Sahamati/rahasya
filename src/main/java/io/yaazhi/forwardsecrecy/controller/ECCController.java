package io.yaazhi.forwardsecrecy.controller;

import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.yaazhi.forwardsecrecy.dto.CipherParameter;
import io.yaazhi.forwardsecrecy.dto.CipherResponse;
import io.yaazhi.forwardsecrecy.dto.ErrorInfo;
import io.yaazhi.forwardsecrecy.dto.KeyMaterial;
import io.yaazhi.forwardsecrecy.dto.SecretKeySpec;
import io.yaazhi.forwardsecrecy.dto.SerializedKeyPair;
import io.yaazhi.forwardsecrecy.dto.SerializedSecretKey;
import io.yaazhi.forwardsecrecy.service.DHEService;
import io.yaazhi.forwardsecrecy.service.ECCService;
import io.yaazhi.forwardsecrecy.service.CipherService;
import lombok.extern.java.Log;

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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;


@Log
@RestController
@RequestMapping("/ecc/v1")
public class ECCController {

    @Autowired
    private ECCService eccService;
    @Autowired
    private DHEService dheService;
    @Autowired
    private CipherService cipherService;

    @ApiOperation(value = "Generate a new ecc key pair")
    @GetMapping(value="/generateKey", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully created"),
			@ApiResponse(code = 400, message = " Request body passed  is null or invalid"),
			@ApiResponse(code = 500, message = " Error occured") })
    public SerializedKeyPair generateKey() {
        try {
            log.info("Generate Key");
            return eccService.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex){
            log.log(Level.SEVERE, "Unable to generateKey");
            final SerializedKeyPair errorKeyPair = new SerializedKeyPair("", new KeyMaterial());
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    @ApiOperation(value = "Generate the shared key for the given remote public key (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) ")
    @PostMapping(value = "/getSharedKey", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully derived the key"),
            @ApiResponse(code = 500, message = " error occured while deriving secret key") })
    public SerializedSecretKey getSharedKey(@RequestBody final SecretKeySpec spec) {
        try {
            log.info("Generate Shared Secret");
            log.log(Level.FINE, "Get PrivateKey");
            final Key ourPrivateKey = eccService.getPEMDecodedStream(spec.getOurPrivateKey());
            log.log(Level.FINE, "Get PublicKey");
            final Key ourPublicKey = eccService.getPEMDecodedStream(spec.getRemotePublicKey());
            log.log(Level.FINE, "Got the key decoded. Lets generate secret key");
            final String secretKey = dheService.getSharedSecret((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey);
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
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

    @ApiOperation(value = "Encrypt the data for the given key material (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) , remote nonce (base64) and local nonce (base64). Send the input data as a base64 string. Encryption happens after decoding the base64")
    @PostMapping(value = "/encrypt", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 200, message = " successfully encrypted the data"),
			@ApiResponse(code = 500, message = " error occured while encrypting the given data") })
    public CipherResponse encrypt(@RequestBody final CipherParameter cipherParam) {
        try {
            log.info("Encrypt complete data");
            log.log(Level.FINE, "Get PrivateKey");
            final Key ourPrivateKey = eccService.getPEMDecodedStream(cipherParam.getOurPrivateKey());
            log.log(Level.FINE, "Get PublicKey");
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no 
            Date expiryDate;
            try {
                expiryDate = df.parse(cipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
            }
            catch(ParseException ex){
                throw new InvalidKeyException("Unable to parse date");
            }
            
            if (!expiryDate.after(new Date())){
                throw new InvalidKeyException("Expired Key");
            }
            final Key ourPublicKey = eccService.getPEMDecodedStream(cipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
            log.log(Level.FINE, "Initiate Encryption");
            String result= cipherService.encrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, cipherParam.getBase64YourNonce(), cipherParam.getBase64RemoteNonce(), cipherParam.getBase64Data());
            log.log(Level.FINE, "Completed Encryption");
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException  ex) {

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
			@ApiResponse(code = 500, message = " error occured while encrypting the given data") })
    public CipherResponse decrypt(@RequestBody final CipherParameter cipherParam) {
        try {
            log.info("Decrypt complete data");
            log.log(Level.FINE, "Get PrivateKey");
            final Key ourPrivateKey = eccService.getPEMDecodedStream(cipherParam.getOurPrivateKey());
            log.log(Level.FINE, "Get PublicKey");
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no 
            Date expiryDate;
            try {
                expiryDate = df.parse(cipherParam.getRemoteKeyMaterial().getDhPublicKey().getExpiry());
            }
            catch(ParseException ex){
                throw new InvalidKeyException("Unable to parse date");
            }
            
            if (!expiryDate.after(new Date())){
                throw new InvalidKeyException("Expired Key");
            }
            final Key ourPublicKey = eccService.getPEMDecodedStream(cipherParam.getRemoteKeyMaterial().getDhPublicKey().getKeyValue());
            log.log(Level.FINE, "Initiate Decryption");
            String result= cipherService.decrypt((PrivateKey) ourPrivateKey, (PublicKey) ourPublicKey, cipherParam.getBase64YourNonce(), cipherParam.getBase64RemoteNonce(), cipherParam.getBase64Data());
            log.log(Level.FINE, "Completed Decryption");
            return new CipherResponse(result, null);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {

            log.log(Level.SEVERE, "Error during decryption");
            final ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            return new CipherResponse("", error);
        }
        
    }
    
}