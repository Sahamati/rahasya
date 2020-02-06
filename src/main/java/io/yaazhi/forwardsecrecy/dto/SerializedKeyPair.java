package io.yaazhi.forwardsecrecy.dto;

import org.springframework.lang.Nullable;

import lombok.Data;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
public class SerializedKeyPair{

    @NonNull
    final private String publicKey;
    @NonNull
    final private String privateKey;
    @Nullable
    ErrorInfo errorInfo;
}

