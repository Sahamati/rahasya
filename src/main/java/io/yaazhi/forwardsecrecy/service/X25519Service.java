package io.yaazhi.forwardsecrecy.service;

import io.yaazhi.forwardsecrecy.dto.DHPublicKey;
import io.yaazhi.forwardsecrecy.dto.KeyMaterial;
import io.yaazhi.forwardsecrecy.dto.SerializedKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
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

@Service
public class X25519Service {
    @Value("${forwardsecrecy.ecc.algorithm:X25519}")
    String algorithm;
    @Value("${forwardsecrecy.ecc.provider:BC}")
    String provider;
    @Value("${forwardsecrecy.ecc.keyExpiryDays:30}")
    int keyExpiry;


    private KeyPair generateKey()
            throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance(algorithm, provider);
        return kpg.genKeyPair();
    }

    public SerializedKeyPair getKeyPair()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {

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
        final KeyMaterial keyMaterial = new KeyMaterial("X25519","","",dhPublicKey);
        final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(privateKey, keyMaterial);
        return serializedKeyPair;
    }

    public String getPEMEncodedStream(Key key, boolean privateKey) throws IOException {

        String keyDescription = privateKey ? "PRIVATE KEY" : "PUBLIC KEY";
        StringWriter writer = new StringWriter();
        PemObject pemObject = new PemObject(keyDescription, key.getEncoded());
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(pemObject);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public Key getPEMDecodedStream(final String pemEncodedKey, boolean privateKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        String encodedKey = pemEncodedKey
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\r", "")
                .replaceAll("\n", "");

        final byte[] pkcs8EncodedKey = Base64.getDecoder().decode(encodedKey);
        KeyFactory factory = KeyFactory.getInstance(algorithm, provider);

        if(privateKey) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8EncodedKey);
            return factory.generatePrivate(spec);
        } else {
            KeySpec keySpec = new X509EncodedKeySpec(pkcs8EncodedKey);
            return factory.generatePublic(keySpec);
        }
    }

    /**
     * Gets the shared secret for X25119 
     * @param ourPrivateKey
     * @param ourPublicKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    public String getSharedSecret(String ourPrivateKey, String ourPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, IOException {
        final byte[] publicKey = getPublicKeyBytes(ourPublicKey);
        final byte[] privateKey = getPrivateKeyBytes(ourPrivateKey);
        return this.getSharedSecret(privateKey, publicKey);
    }

    /***
     * Get shared secret with the private and public key object.
     * @param ourPrivateKey
     * @param ourPublicKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    public String getSharedSecret(PrivateKey ourPrivateKey, PublicKey ourPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, IOException {
        final byte[] publicKey = getPublicKeyBytes(ourPublicKey);
        final byte[] privateKey = getPrivateKeyBytes(ourPrivateKey);
        return this.getSharedSecret(privateKey, publicKey);
    }

    private byte[] getPrivateKeyBytes(String privatekey) 
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
        if(privatekey.length() == 64){ //the key is 32 bytes so 64 bytes when hex encoded.
            return Hex.decode(privatekey);
        }
        //Else we will assume its a PEM encoded
        final Key ourPrivateKey = this.getPEMDecodedStream(privatekey, true);
        return getPrivateKeyBytes((PrivateKey) ourPrivateKey);
    }

    private byte[] getPrivateKeyBytes(PrivateKey privatekey) throws IOException{
        X25519PrivateKeyParameters x25519PrivateKeyParameters = (X25519PrivateKeyParameters) PrivateKeyFactory.createKey(privatekey.getEncoded());
        return x25519PrivateKeyParameters.getEncoded();
    }

    private byte[] getPublicKeyBytes(String publicKey) 
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
        if(publicKey.length() == 64){ //the key is 32 bytes so 64 bytes when hex encoded.
            return Hex.decode(publicKey);
        }
        //Else we will assume its a PEM encoded
        final Key ourPublicKey = this.getPEMDecodedStream(publicKey, false);
        return getPublicKeyBytes((PublicKey) ourPublicKey);
    }

    private byte[] getPublicKeyBytes(PublicKey publicKey) 
            throws IOException {
        X25519PublicKeyParameters x25519PublicKeyParameters = (X25519PublicKeyParameters) PublicKeyFactory.createKey(publicKey.getEncoded());
        return x25519PublicKeyParameters.getEncoded();
    }

    private String getSharedSecret(byte[] ourPrivatekey, byte[] remotePublicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, IOException {
        byte[] secretKey = new byte[X25519.POINT_SIZE];
        if(remotePublicKey.length != 32 || ourPrivatekey.length != 32) {
            //the key is 32 bytes so 64 bytes when hex encoded.
            throw new InvalidKeyException();
        }
        X25519.scalarMult(ourPrivatekey, 0, remotePublicKey, 0, secretKey, 0);
        return Base64.getEncoder().encodeToString(secretKey);
    } 

}
