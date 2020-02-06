package io.yaazhi.forwardsecrecy.dto;

import org.springframework.lang.Nullable;

import lombok.Data;
import lombok.ToString;

@ToString(includeFieldNames=true)
@Data
public class ErrorInfo{
    @Nullable 
    private String errorCode;
    @Nullable
    private String errorMessage;
    @Nullable
    private ErrorInfo errorInfo; 
}

