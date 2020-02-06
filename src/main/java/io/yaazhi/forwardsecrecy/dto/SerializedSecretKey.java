package io.yaazhi.forwardsecrecy.dto;

import org.springframework.lang.Nullable;

import lombok.Data;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
public class SerializedSecretKey{

    @NonNull
    final private String key;
    @Nullable
    ErrorInfo errorInfo;
}

