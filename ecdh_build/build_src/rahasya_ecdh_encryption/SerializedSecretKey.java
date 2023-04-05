package rahasya_ecdh_encryption;


public class SerializedSecretKey {

    final private String key;
    ErrorInfo errorInfo;

    public SerializedSecretKey (String key) {

        this.key = key;
    }

    public String getKey () {

        return key;
    }

    public void setErrorInfo (ErrorInfo errorInfo) {

        this.errorInfo = errorInfo;
    }

    public ErrorInfo getErrorInfo () {

        return errorInfo;
    }

}
