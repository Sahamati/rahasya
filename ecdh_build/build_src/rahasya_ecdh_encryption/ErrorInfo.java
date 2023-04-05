package rahasya_ecdh_encryption;

public class ErrorInfo {

    private String errorCode;
    private String errorMessage;
    private ErrorInfo errorInfo;
    
    public ErrorInfo () {

    }

    public ErrorInfo (String errorCode, String errorMessage, ErrorInfo errorInfo) {

        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.errorInfo = errorInfo;
    }

    public String getErrorCode () {

        return errorCode;
    }

    public String getErrorMessage () {


        return errorMessage;
    }

    public ErrorInfo getErrorInfo () {

        return errorInfo;
    }

    public void setErrorCode (String errorCode) {

        this.errorCode = errorCode;
    }

    public void setErrorMessage (String errorMessage) {

        this.errorMessage = errorMessage;
    }

    public void setErrorInfo (ErrorInfo errorInfo) {

        this.errorInfo = errorInfo;
    }

}
