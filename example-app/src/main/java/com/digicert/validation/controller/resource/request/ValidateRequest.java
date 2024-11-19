package com.digicert.validation.controller.resource.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidateRequest {
    public String domain;
    public String filename;
    public String emailAddress;
    public String randomValue;

    public String tokenValue;

    public DcvRequestType dcvRequestType;
}
