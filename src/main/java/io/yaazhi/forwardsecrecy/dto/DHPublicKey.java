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
public class DHPublicKey{
    @NonNull
    String expiry;
    //Dont ask me why this is capital. I am just blindly following the spec ;)
    @NonNull
    @JsonProperty("Parameters")
    String parameters;
    @NonNull
    @JsonProperty("KeyValue")
    String keyValue;
}
