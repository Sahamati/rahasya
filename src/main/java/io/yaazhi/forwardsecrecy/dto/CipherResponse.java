package io.yaazhi.forwardsecrecy.dto;

import io.micrometer.core.lang.Nullable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CipherResponse{
    @NonNull
    String base64Data;
    @Nullable
    ErrorInfo errorInfo;
   
}

