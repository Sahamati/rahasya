package io.yaazhi.forwardsecrecy.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.lang.Nullable;

import lombok.Data;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
public class SerializedKeyPair{
    @NonNull
    final private String privateKey;
    @NonNull
    @JsonProperty("KeyMaterials")
    KeyMaterial keyMaterials;
    @Nullable
    ErrorInfo errorInfo;
}

