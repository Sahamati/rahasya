package rahasya_ecdh_encryption;

public class EncryptCipherParameter{

    KeyMaterial remoteKeyMaterial;
    String ourPrivateKey;
    String base64YourNonce;
    String base64RemoteNonce;
    String data;

    public EncryptCipherParameter () {

    }

    public EncryptCipherParameter (KeyMaterial remoteKeyMaterial, String ourPrivateKey, String base64YourNonce, String base64RemoteNonce, String data) {

    }

    public KeyMaterial getRemoteKeyMaterial () {

        return remoteKeyMaterial;
    }

    public String getBase64YourNonce () {

        return base64YourNonce;
    }

    public String getBase64RemoteNonce () {

        return base64RemoteNonce;
    }
    public String getOurPrivateKey () {

        return ourPrivateKey;
    }

    public String getData () {

        return data;
    }

    public void setRemoteKeyMaterial (KeyMaterial remoteKeyMaterial) {

        this.remoteKeyMaterial = remoteKeyMaterial;
    }

    public void setBase64YourNonce (String base64YourNonce) {

        this.base64YourNonce = base64YourNonce;
    }

    public void setBase64RemoteNonce (String base64RemoteNonce) {

        this.base64RemoteNonce = base64RemoteNonce;
    }
    public void setOurPrivateKey (String ourPrivateKey) {

        this.ourPrivateKey =  ourPrivateKey;
    }

    public void setData (String data) {

        this.data =  data;
    }

}

