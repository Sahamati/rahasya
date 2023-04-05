package rahasya_ecdh_encryption;

public class DecryptCipherParameter{

    KeyMaterial remoteKeyMaterial;
    String ourPrivateKey;
    String base64YourNonce;
    String base64RemoteNonce;
    String base64Data;


    public DecryptCipherParameter () {

    }

    public DecryptCipherParameter (KeyMaterial remoteKeyMaterial, String ourPrivateKey,String base64YourNonce,
    String base64RemoteNonce, String base64Data) {

        this.remoteKeyMaterial  = remoteKeyMaterial;
        this.ourPrivateKey      = ourPrivateKey;
        this.base64YourNonce    = base64YourNonce;
        this.base64RemoteNonce  = base64RemoteNonce;
        this.base64Data         = base64Data;
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

    public String getBase64Data () {

        return base64Data;
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

    public void setBase64Data (String base64Data) {

        this.base64Data =  base64Data;
    }
}