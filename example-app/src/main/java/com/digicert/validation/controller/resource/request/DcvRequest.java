package com.digicert.validation.controller.resource.request;

public record DcvRequest(String domain,
                         String filename,
                         String accountUri,
                         long accountId,
                         DcvRequestType dcvRequestType) {
    public DcvRequest(String domain, long accountId, DcvRequestType dcvRequestType) {
        this(domain, null, null, accountId, dcvRequestType);
    }

    public DcvRequest(String domain, String filename, long accountId, DcvRequestType dcvRequestType) {
        this(domain, filename, null, accountId, dcvRequestType);
    }
}
