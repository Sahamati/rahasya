package io.yaazhi.forwardsecrecy.controller;

import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Level;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.yaazhi.forwardsecrecy.dto.ErrorInfo;
import io.yaazhi.forwardsecrecy.dto.SecretKeySpec;
import io.yaazhi.forwardsecrecy.dto.SerializedKeyPair;
import io.yaazhi.forwardsecrecy.dto.SerializedSecretKey;
import io.yaazhi.forwardsecrecy.service.DHEService;
import io.yaazhi.forwardsecrecy.service.ECCService;
import lombok.extern.java.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

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

    @ApiOperation(value = "Generate a new ecc key pair")
    @GetMapping(value="/generateKey", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully created"),
			@ApiResponse(code = 400, message = " Request body passed  is null or invalid"),
			@ApiResponse(code = 500, message = " Error occured") })
    public SerializedKeyPair generateKey() {
        try {
            log.info("Generate Key");
            return eccService.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex){
            log.log(Level.SEVERE, "Unable to generateKey");
            SerializedKeyPair errorKeyPair = new SerializedKeyPair("", "");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    @ApiOperation(value = "Generate the shared key for the given remote public key (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) ")
    @PostMapping(value = "/getSharedKey", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully derived the key"),
			@ApiResponse(code = 500, message = " error occured while deriving secret key") })
    public SerializedSecretKey getSharedKey(@RequestBody SecretKeySpec spec) {
        try {
            log.info("Generate Shared Secret");
            log.log(Level.FINE, "Get PrivateKey");
            Key ourPrivateKey = eccService.getPEMDecodedStream(spec.getOurPrivateKey());
            log.log(Level.FINE, "Get PublicKey");
            Key ourPublicKey = eccService.getPEMDecodedStream(spec.getRemotePublicKey());
            log.log(Level.FINE, "Got the key decoded. Lets generate secret key");
            final String secretKey = dheService.getSharedSecret(
                    (PrivateKey) ourPrivateKey,
                    (PublicKey) ourPublicKey);
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException ex) {
            log.log(Level.SEVERE, "Error when deriving secret key");
            SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }
        
    }
    
    
    
}