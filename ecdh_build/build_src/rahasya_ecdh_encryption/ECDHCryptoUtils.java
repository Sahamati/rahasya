package rahasya_ecdh_encryption;

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

public  class ECDHCryptoUtils  {

    static X25519Controller x25519Controller = new X25519Controller ();
    static ECCController eccController = new ECCController();
    
    public static  Map <String, String> GenerateKeyMaterial (String CurveType, String ExpiryDate) {

        Map<String, String> keyMap = new HashMap<>();

        String base64Nonce = GenerateRandomBase64Nonce ();

        switch (CurveType.toLowerCase()) {

            case "ecc" : {
                final SerializedKeyPair keyPair = eccController.generateKey();
                String publicKey  = keyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
                String privateKey = keyPair.getPrivateKey();
                keyMap.put ("privateKey", privateKey);
                keyMap.put ("publicKey", publicKey);
                keyMap.put ("expiry",ExpiryDate);
                keyMap.put ("nonce", base64Nonce);
                keyMap.put ("curveType", CurveType);
                break;
            }
            case "x25519" :
            default:  {

                String curveType  = "x25519";
                final SerializedKeyPair keyPair = x25519Controller.generateKey();
                String publicKey  = keyPair.getKeyMaterial().getDhPublicKey().getKeyValue();
                String privateKey = keyPair.getPrivateKey();
                keyMap.put ("privateKey", privateKey);
                keyMap.put ("publicKey", publicKey);
                keyMap.put ("expiry",ExpiryDate);
                keyMap.put("nonce", base64Nonce);
                keyMap.put ("curveType", curveType);
                break;
            }
        }

        return keyMap;
    }

    public static String GenerateRandomBase64Nonce () {

        SecureRandom secureRandom = new SecureRandom();
        byte nonce[] = new byte[32];
        secureRandom.nextBytes(nonce);
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        return nonceBase64;
    }

    public static String GetDate (int Hour) {
        Date date = new Date();
        Calendar cl = Calendar. getInstance();
        cl.setTime(date);
        cl.add(Calendar.HOUR, Hour);
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(tz);
        String expiryAsISO = df.format(cl.getTime());
        return expiryAsISO;
    }

    public static String EncryptDataECDH (String CurveType, String ClientPublicKey, String ClientNonce,
    String ClientExpiryDate,
    Map <String, String> ServerKEYMaterialMap,  String DataToBeEncrypted
    ) {

          String ServerNonce = ServerKEYMaterialMap.get("nonce");
          String ServerPrivateKey = ServerKEYMaterialMap.get("privateKey");
          switch (CurveType.toLowerCase()) {

            case "ecc" : {

                final DHPublicKey dhPublicKey = new DHPublicKey(ClientExpiryDate, "", ClientPublicKey);
                final KeyMaterial keyMaterial = new KeyMaterial("ECDH", "Curve25519", "", dhPublicKey);
                final SerializedKeyPair serverSerializedKeyPair = new SerializedKeyPair(ServerPrivateKey, keyMaterial);

                EncryptCipherParameter encryptCipherParam = new EncryptCipherParameter();
                encryptCipherParam.setData(DataToBeEncrypted);
                encryptCipherParam.setBase64RemoteNonce(ClientNonce);
                encryptCipherParam.setBase64YourNonce(ServerNonce);
                encryptCipherParam.setOurPrivateKey(serverSerializedKeyPair.getPrivateKey());
                encryptCipherParam.setRemoteKeyMaterial(serverSerializedKeyPair.getKeyMaterial());
                CipherResponse encryptedCipherResponse = eccController.encrypt(encryptCipherParam);
                return encryptedCipherResponse.getBase64Data();
            }
            case "x25519" : 
            default: {
                final DHPublicKey dhPublicKey = new DHPublicKey(ClientExpiryDate, "", ClientPublicKey);
                final KeyMaterial keyMaterial = new KeyMaterial("X25519", "", "", dhPublicKey);
                final SerializedKeyPair serverSerializedKeyPair = new SerializedKeyPair(ServerPrivateKey, keyMaterial);

                EncryptCipherParameter encryptCipherParam = new EncryptCipherParameter();
                encryptCipherParam.setData(DataToBeEncrypted);
                encryptCipherParam.setBase64RemoteNonce(ClientNonce);
                encryptCipherParam.setBase64YourNonce(ServerNonce);
                encryptCipherParam.setOurPrivateKey(serverSerializedKeyPair.getPrivateKey());
                encryptCipherParam.setRemoteKeyMaterial(serverSerializedKeyPair.getKeyMaterial());
                CipherResponse encryptedCipherResponse = x25519Controller.encrypt(encryptCipherParam);
                return encryptedCipherResponse.getBase64Data();
            }
        }
    }

    public static String DecryptDataECDH (String CurveType, String ServerPublicKey, String ServerNonce,
    String ServerExpiryDate,
    Map <String, String> ClientKEYMaterialMap,  String DataToBeDecrypted
    ) {

          Map <String, String> encryptedData;

          String ClientNonce = ClientKEYMaterialMap.get("nonce");
          String ClientPrivateKey = ClientKEYMaterialMap.get("privateKey");
          switch (CurveType.toLowerCase()) {

            case "ecc" :{
                final DHPublicKey dhPublicKey = new DHPublicKey(ServerExpiryDate, "", ServerPublicKey);
                final KeyMaterial keyMaterial = new KeyMaterial("ECDH", "Curve25519", "", dhPublicKey);
                final SerializedKeyPair serverSerializedKeyPair = new SerializedKeyPair(ClientPrivateKey, keyMaterial);

                DecryptCipherParameter decryptCipherParam = new DecryptCipherParameter();
                decryptCipherParam.setBase64Data(DataToBeDecrypted);
                decryptCipherParam.setBase64RemoteNonce(ServerNonce);
                decryptCipherParam.setBase64YourNonce(ClientNonce);
                decryptCipherParam.setOurPrivateKey(serverSerializedKeyPair.getPrivateKey());
                decryptCipherParam.setRemoteKeyMaterial(serverSerializedKeyPair.getKeyMaterial());
                CipherResponse decryptedCipherResponse = eccController.decrypt(decryptCipherParam);
                return new String(Base64.getDecoder().decode(decryptedCipherResponse.getBase64Data()));
            }
           
            case "x25519" : 
            default: {
                final DHPublicKey dhPublicKey = new DHPublicKey(ServerExpiryDate, "", ServerPublicKey);
                final KeyMaterial keyMaterial = new KeyMaterial("X25519", "", "", dhPublicKey);
                final SerializedKeyPair serverSerializedKeyPair = new SerializedKeyPair(ClientPrivateKey, keyMaterial);

                DecryptCipherParameter decryptCipherParam = new DecryptCipherParameter();
                decryptCipherParam.setBase64Data(DataToBeDecrypted);
                decryptCipherParam.setBase64RemoteNonce(ServerNonce);
                decryptCipherParam.setBase64YourNonce(ClientNonce);
                decryptCipherParam.setOurPrivateKey(serverSerializedKeyPair.getPrivateKey());
                decryptCipherParam.setRemoteKeyMaterial(serverSerializedKeyPair.getKeyMaterial());
                CipherResponse decryptedCipherResponse = x25519Controller.decrypt(decryptCipherParam);
                return new String(Base64.getDecoder().decode(decryptedCipherResponse.getBase64Data()));
            }
        }
 
    }

}