package rahasya_ecdh_encryption;

public class SerializedKeyPair {
    
    final private String privateKey;
    KeyMaterial keyMaterial;
    ErrorInfo errorInfo;

    public SerializedKeyPair (String privateKey, KeyMaterial keyMaterial) {

        this.privateKey = privateKey;
        this.keyMaterial = keyMaterial;
    }

    public KeyMaterial getKeyMaterial() {

        return keyMaterial;
    }

    public String getPrivateKey () {

        return privateKey;
    }

    public ErrorInfo getErrorInfo () {

        return errorInfo;
    }

    public void setKeyMaterial(KeyMaterial keyMaterial) {

        this.keyMaterial = keyMaterial;
    }

    public void setErrorInfo (ErrorInfo errorInfo) {

        this.errorInfo = errorInfo;
    }


}
