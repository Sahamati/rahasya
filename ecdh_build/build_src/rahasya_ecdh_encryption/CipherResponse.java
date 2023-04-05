package rahasya_ecdh_encryption;
public class CipherResponse{

    String base64Data;
    ErrorInfo errorInfo;

    public CipherResponse () {

    }

    public CipherResponse (String base64Data, ErrorInfo errorInfo) {

        this.base64Data = base64Data;
        this.errorInfo  = errorInfo;
    }

    public String getBase64Data () {

        return base64Data;
    }

    public ErrorInfo getErrorInfo () {

        return errorInfo;
    }

    public void setBase64Data (String base64Data) {

        this.base64Data = base64Data;
    }

    public void setErrorInfo (ErrorInfo errorInfo) {

        this.errorInfo = errorInfo;
    }

}
