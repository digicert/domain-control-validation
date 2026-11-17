package com.digicert.validation.controller.resource.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidateRequest {
    public String domain;
    public String filename;
    public String emailAddress;
    public String randomValue;
    public String accountUri;
    /** Account-key thumbprints to try, most likely first. Only used for ACME_DNS_PERSIST. */
    public List<String> accountThumbprints;

    public String tokenValue;

    public DcvRequestType dcvRequestType;
}
