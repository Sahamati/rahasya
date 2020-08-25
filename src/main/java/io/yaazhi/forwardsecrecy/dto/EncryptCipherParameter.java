package io.yaazhi.forwardsecrecy.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EncryptCipherParameter{

    @NonNull
    KeyMaterial remoteKeyMaterial;
    @NonNull
    String ourPrivateKey;
    @NonNull
    String base64YourNonce;
    @NonNull
    String base64RemoteNonce;
    @NonNull
    String data;
   
}

