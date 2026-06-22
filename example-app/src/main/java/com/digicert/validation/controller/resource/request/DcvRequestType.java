package com.digicert.validation.controller.resource.request;

public enum DcvRequestType {
    EMAIL_DNS_TXT,
    EMAIL_CONSTRUCTED,
    EMAIL_DNS_CAA,
    DNS_TXT,
    DNS_CNAME,
    DNS_TXT_TOKEN,
    DNS_TXT_PERSISTENT,
    FILE_VALIDATION,
    FILE_VALIDATION_TOKEN,
    ACME_DNS,
    ACME_HTTP
}
