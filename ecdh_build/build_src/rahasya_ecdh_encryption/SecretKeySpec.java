package rahasya_ecdh_encryption;

public class SecretKeySpec {

    String remotePublicKey;
    String ourPrivateKey;
    
    public SecretKeySpec() {

    }

    public SecretKeySpec (String remotePublicKey, String ourPrivateKey) {

        this.remotePublicKey = remotePublicKey;
        this.ourPrivateKey = ourPrivateKey;

    }

    public void  setRemotePublicKey (String remotePublicKey) {

        this.remotePublicKey = remotePublicKey;
    }

    public void setOurPrivateKey (String ourPrivateKey) {

        this.ourPrivateKey = ourPrivateKey;
    }

    public String getRemotePublicKey () {

        return remotePublicKey;
    }

    public String getOurPrivateKey () {

        return ourPrivateKey;
    }

}

