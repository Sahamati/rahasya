package rahasya_ecdh_encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import java.security.spec.ECParameterSpec;

public class ECCService {
    String curve = "Curve25519";
    String algorithm = "EC";
    String keyDerivationAlgorithm = "ECDH";
    String provider = "BC";
    int keyExpiry = 24;
    

    private KeyPair generateKey()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance(algorithm, provider);

        X9ECParameters ecP = CustomNamedCurves.getByName(curve);
        ECParameterSpec ecSpec = EC5Util.convertToSpec(ecP);
        kpg.initialize(ecSpec);

        final KeyPair kp = kpg.genKeyPair();
        return kp;
    }

    public SerializedKeyPair getKeyPair()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final KeyPair kp = this.generateKey();
        final String privateKey = this.getPEMEncodedStream(kp.getPrivate(),true);
        final String publicKey = this.getPEMEncodedStream(kp.getPublic(), false);
        Date date = new Date();
        Calendar cl = Calendar. getInstance();
        cl.setTime(date);
        cl.add(Calendar.HOUR, keyExpiry);
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
        df.setTimeZone(tz);
        String expiryAsISO = df.format(cl.getTime());
        final DHPublicKey dhPublicKey = new DHPublicKey(expiryAsISO,"",publicKey);
        final KeyMaterial keyMaterial = new KeyMaterial(keyDerivationAlgorithm,curve,"",dhPublicKey);
        final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(privateKey, keyMaterial);
        return serializedKeyPair;
    }

    private String getPEMEncodedStream(final Key key, boolean privateKey) {

        
        final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
        final StringBuilder sb = new StringBuilder();
        final String keyType = privateKey ? "PRIVATE" : "PUBLIC";
        sb.append("-----BEGIN " + keyType + " KEY-----");
        sb.append(new String(Base64.getEncoder().encode(pkcs8KeySpec.getEncoded())));
        sb.append("-----END " + keyType + " KEY-----");
        return sb.toString();
    }

    public Key getPEMDecodedStream(final String pemEncodedKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
                
        boolean privateKey = false;
        String encodedKey = "";
        
        if (pemEncodedKey.startsWith("-----BEGIN PRIVATE KEY-----")) {
            privateKey = true;
            encodedKey = pemEncodedKey.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "");
        } else {
            encodedKey = pemEncodedKey.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "");
        }
        
        final byte[] pkcs8EncodedKey = Base64.getDecoder().decode(encodedKey);
        
        KeyFactory factory = KeyFactory.getInstance(algorithm, provider);

        if(privateKey){
            KeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedKey);
            //This does not mean the key is in correct format. If you receive invalid key spec error then the encoding is not correct.
            return factory.generatePrivate(keySpec);
        }
        KeySpec keySpec = new X509EncodedKeySpec(pkcs8EncodedKey);        
        //This does not mean the key is in correct format. If you receive invalid key spec error then the encoding is not correct.
        return factory.generatePublic(keySpec);
        }

    }

