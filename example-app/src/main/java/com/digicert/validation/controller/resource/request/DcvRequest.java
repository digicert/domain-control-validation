package com.digicert.validation.controller.resource.request;

public record DcvRequest(String domain,
                         String filename,
                         long accountId,
                         DcvRequestType dcvRequestType) {
    public DcvRequest(String domain, long accountId, DcvRequestType dcvRequestType) {
        this(domain, null, accountId, dcvRequestType);
    }
}
