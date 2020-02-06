package io.yaazhi.forwardsecrecy.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
public class SecretKeySpec{

    @NonNull
    String remotePublicKey;
    @NonNull
    String ourPrivateKey;
    
    public SecretKeySpec() {}
}

