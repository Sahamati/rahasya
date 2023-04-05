package rahasya_ecdh_encryption;


public class DHPublicKey {

    String  expiry;
    String  parameters;
    String  keyValue;

    public DHPublicKey (String expiry, String parameters, String keyValue) 
    {
        this.expiry = expiry;
        this.parameters = parameters;
        this.keyValue = keyValue;
    }

    public DHPublicKey () {}

    public void setExpiry(String  expiry) 
    {
        this.expiry = expiry;
    }

    public void setParameters(String parameters) {

        this.parameters = parameters;
    }

    public void setKeyValue (String keyValue) 
    {
        this.keyValue = keyValue;
    }

    public String getExpiry () 
    {
        return expiry;
    }
    
    public String getParameters() {

        return parameters;
    }
    
    public String getKeyValue() {

        return keyValue;
    }

}

