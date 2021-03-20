package io.yaazhi.forwardsecrecy.service;

import io.yaazhi.forwardsecrecy.dto.DHPublicKey;
import io.yaazhi.forwardsecrecy.dto.KeyMaterial;
import io.yaazhi.forwardsecrecy.dto.SerializedKeyPair;
import lombok.extern.java.Log;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;

@Log
@Service
public class X25519Service {
    @Value("${forwardsecrecy.ecc.algorithm:X25519}")
    String algorithm;
    @Value("${forwardsecrecy.ecc.provider:BC}")
    String provider;
    @Value("${forwardsecrecy.ecc.keyExpiryDays:30}")
    int keyExpiry;
    private SecureRandom random = new SecureRandom();


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
        StringReader reader = new StringReader(pemEncodedKey);
        PemReader pemReader = new PemReader(reader);
        if(privateKey) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
            return KeyFactory.getInstance(algorithm, provider).generatePrivate(spec);
        }
        else {
            KeySpec keySpec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
            return KeyFactory.getInstance(algorithm, provider).generatePublic(keySpec);
        }
    }

}
