import java.util.Date;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.Base64;
import java.text.SimpleDateFormat;
import java.security.SecureRandom;
import java.security.Security;
import java.text.DateFormat;
import java.util.HashMap;
import java.util.Map;

import rahasya_ecdh_encryption.X25519Controller;
import rahasya_ecdh_encryption.SerializedKeyPair;
import rahasya_ecdh_encryption.SecretKeySpec;
import rahasya_ecdh_encryption.SerializedSecretKey;
import rahasya_ecdh_encryption.DHPublicKey;
import rahasya_ecdh_encryption.KeyMaterial;
import rahasya_ecdh_encryption.SerializedKeyPair;
import rahasya_ecdh_encryption.EncryptCipherParameter;
import rahasya_ecdh_encryption.CipherResponse;
import rahasya_ecdh_encryption.DecryptCipherParameter;

class X25519Main {

    static X25519Controller x25519Controller = new X25519Controller();

    public static String GenerateRandomBase64Nonce () {

        SecureRandom secureRandom = new SecureRandom();
        byte nonce[] = new byte[32];
        secureRandom.nextBytes(nonce);
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        return nonceBase64;
    }

    public static Map <String, String> getPrivatePublicKey () {

        final SerializedKeyPair keyPair = x25519Controller.generateKey();
        Map<String, String> keyMap = new HashMap<>();
        
        if (keyPair.getErrorInfo() != null) {

            System.out.println(keyPair.getErrorInfo().getErrorMessage());
        } else {
            String publicKey  = keyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
            String privateKey = keyPair.getPrivateKey();
            keyMap.put ("privateKey", privateKey);
            keyMap.put ("publicKey", publicKey);
            keyMap.put ("expiry",keyPair.getKeyMaterial().getDhPublicKey().getExpiry());
        }

        return keyMap;
    }

    // public static String getExpiryDate (int hour) {

    //     Date date = new Date();
    //     Calendar cl = Calendar. getInstance();
    //     cl.setTime(date);
    //     cl.add(Calendar.HOUR, hour);
    //     TimeZone tz = TimeZone.getTimeZone("UTC");
    //     DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    //     df.setTimeZone(tz);
    //     String expiryAsISO = df.format(cl.getTime());
    //     return expiryAsISO;
    // }

    public static String encryptData (
        String clientPublicKey, String serverPrivateKey, String  clientNonce,
        String serverNonce, String data, String expiry
    ) {
        try {

        final DHPublicKey dhPublicKey = new DHPublicKey(expiry, "", clientPublicKey);
        final KeyMaterial keyMaterial = new KeyMaterial("X25519", "", "", dhPublicKey);
        final SerializedKeyPair serverSerializedKeyPair = new SerializedKeyPair(serverPrivateKey, keyMaterial);

        EncryptCipherParameter encryptCipherParam = new EncryptCipherParameter();
        encryptCipherParam.setData(data);
        encryptCipherParam.setBase64RemoteNonce(clientNonce);
        encryptCipherParam.setBase64YourNonce(serverNonce);
        encryptCipherParam.setOurPrivateKey(serverSerializedKeyPair.getPrivateKey());
        encryptCipherParam.setRemoteKeyMaterial(serverSerializedKeyPair.getKeyMaterial());
        CipherResponse encryptedCipherResponse = x25519Controller.encrypt(encryptCipherParam);

        if (encryptedCipherResponse.getErrorInfo() != null) {
            // Log the error message instead of printing it
            System.out.println(
                "Error during encryption: {}" + encryptedCipherResponse.getErrorInfo().getErrorMessage()
            );
        } else {
            // Store the encrypted data using the standard put method
            return encryptedCipherResponse.getBase64Data();
        }
        } catch (Exception e) {
        // Log the error message or re-throw the exception
        System.out.println("Error during encryption"+ e);
        }

       return null;
    }

    public static  String decryptData (String serverPublicKey, String clientPrivateKey, String serverNonce, String clientNonce, String data, String expiry) {
        try {

            final DHPublicKey dhPublicKey = new DHPublicKey(expiry,"",serverPublicKey);
            final KeyMaterial keyMaterial = new KeyMaterial("X25519","","",dhPublicKey);
            final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(clientPrivateKey, keyMaterial);
            DecryptCipherParameter decryptCipherParam = new DecryptCipherParameter();
            decryptCipherParam.setBase64Data(data);
            decryptCipherParam.setBase64RemoteNonce(serverNonce);
            decryptCipherParam.setBase64YourNonce(clientNonce);
            decryptCipherParam.setOurPrivateKey(serializedKeyPair.getPrivateKey());
            decryptCipherParam.setRemoteKeyMaterial(serializedKeyPair.getKeyMaterial());

            CipherResponse decryptedCipherResponse = x25519Controller.decrypt(decryptCipherParam);
            if (decryptedCipherResponse.getErrorInfo() != null) {

                System.out.println(
                    "Error in decrypting data: " + decryptedCipherResponse.getErrorInfo().getErrorMessage()
                );
            } else {

                return   new String(Base64.getDecoder().decode(decryptedCipherResponse.getBase64Data()));            
            }            

        } catch (Exception e) {

             System.out.println("Error in decrypting data"+e.toString());
        }
        return null;
    }

    public static Map<String, String>  clientKeysGeneration () {

        Map<String, String> clientKeys = getPrivatePublicKey ();
        String clientNonce = GenerateRandomBase64Nonce ();
        clientKeys.put("nonce",clientNonce);

        System.out.println ("clientPrivateKey : " + clientKeys.get("privateKey"));
        System.out.println ("clientPublicKey : " + clientKeys.get("publicKey"));
        System.out.println ("clientKeyExpiry : " + clientKeys.get("expiry"));
        System.out.println ("clientNonce : " + clientKeys.get("nonce"));
        
        return clientKeys;
    }

    public static Map<String, String> serverSideProcessing (
        String clientPublicKey, String clientNonce,String clientKeyExpiry
    ) {

        Map<String, String> serverKeys = getPrivatePublicKey ();
        String serverNonce = GenerateRandomBase64Nonce ();
        serverKeys.put("nonce",serverNonce);
        String data = "Hello World !";
        String encryptedData = encryptData (
            clientPublicKey, serverKeys.get("privateKey"), clientNonce,
            serverNonce, data, clientKeyExpiry
        );
        serverKeys.put("encryptedData" , encryptedData);
        
        System.out.println("serverPrivateKey : " + serverKeys.get("privateKey"));
        System.out.println("serverPublicKey : " + serverKeys.get("publicKey"));
        System.out.println("serverExpiry : " + serverKeys.get("expiry"));
        System.out.println("serverNonce : " + serverKeys.get("nonce"));
        System.out.println ("data : " + data);
        System.out.println ("encryptedData : " + encryptedData);
        
        return serverKeys;
    }

    public static String clientSideDecryption (
        Map<String, String> clientKeyMaterial, String serverEncryptedData,
        String serverPublicKey, String serverNonce, String serverKeyExpiry
    ) {

        String decryptedData =  decryptData(
            serverPublicKey, clientKeyMaterial.get("privateKey"), serverNonce,
            clientKeyMaterial.get("nonce"), serverEncryptedData, serverKeyExpiry
        );
        System.out.println("DecryptedData : " + decryptedData);
        return decryptedData;
    }

    
    /**
        Below main function is a simulation of syncronous end to end 
        communication between fiu and fip, where fiu is represented as the
        client and fip is represented as the server.
        The client generates a key pair, a nonce, and expiry which it then
        shares with the server.
        The server then generates similar fields and encrypts the data and
        shares it with the client.
        The client decrypts the data.
     */

    public static void main(String[] args) {

        Map<String, String> clientKeyMaterial = clientKeysGeneration ();
        
        String clientPrivateKey = clientKeyMaterial.get("privateKey");
        String clientPublicKey  = clientKeyMaterial.get("publicKey");
        String clientKeyExpiry = clientKeyMaterial.get("expiry");
        String clientNonce = clientKeyMaterial.get("nonce");

        Map<String, String> serverKeyMaterialAndData = serverSideProcessing (
            clientPublicKey, clientNonce, clientKeyExpiry
        );

        String serverEncryptedData = serverKeyMaterialAndData.get("encryptedData");
        String serverPublicKey  = serverKeyMaterialAndData.get("publicKey");
        String serverKeyExpiry = serverKeyMaterialAndData.get("expiry");
        String serverNonce = serverKeyMaterialAndData.get("nonce");
        
        String clientDecryptedData = clientSideDecryption (
            clientKeyMaterial,serverEncryptedData,serverPublicKey,serverNonce,serverKeyExpiry
        );
    }
}
