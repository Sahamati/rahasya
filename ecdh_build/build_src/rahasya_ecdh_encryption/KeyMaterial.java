package rahasya_ecdh_encryption;

public class KeyMaterial {

    String cryptoAlg;
    String curve;
    String params;
    DHPublicKey dhPublicKey;

public    KeyMaterial (String cryptoAlg, String curve, String params, DHPublicKey dhPublicKey) 
    {

        this.cryptoAlg = cryptoAlg;
        this.curve     = curve;
        this.params    = params;
        this.dhPublicKey = dhPublicKey;
    }

   public KeyMaterial () {

    }

    public String getCryptoAlgo() {

        return cryptoAlg;
    }
    public String getCurve() {

        return curve;
    }
    public String getParams() {

        return params;
    }

    public DHPublicKey getDhPublicKey () {

        return dhPublicKey;
    }

    public void setCryptoAlgo(String cryptoAlg) {

        this.cryptoAlg = cryptoAlg;
    }

    public void setCurve(String curve) 
    {
        this.curve = curve;
    }
    public void setParams(String params)
    {
        this.params = params;
    }

    public void setDhPublicKey (DHPublicKey dhPublicKey) 
    {
        this.dhPublicKey = dhPublicKey;
    }
}
