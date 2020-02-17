package io.yaazhi.forwardsecrecy.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class KeyMaterial{
    @NonNull
    String cryptoAlg;
    @NonNull
    String curve;
    @NonNull
    String params;
    @NonNull
    @JsonProperty("DHPublicKey")
    DHPublicKey dhPublicKey;
}
