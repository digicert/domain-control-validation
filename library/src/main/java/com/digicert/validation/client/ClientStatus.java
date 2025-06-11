package com.digicert.validation.client;

/**
 * Enum representing various client statuses for DNS and file operations.
 * Each status corresponds to a specific outcome of a client operation.
 */
public enum ClientStatus {
    DNS_LOOKUP_SUCCESS,
    DNS_LOOKUP_BAD_REQUEST,
    DNS_LOOKUP_RECORD_NOT_FOUND,
    DNS_LOOKUP_TEXT_PARSE_EXCEPTION,
    DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION,
    DNS_LOOKUP_DOMAIN_NOT_FOUND,
    DNS_LOOKUP_TIMEOUT,
    DNS_LOOKUP_IO_EXCEPTION,

    FILE_SUCCESS,
    FILE_BAD_REQUEST,
    FILE_BAD_RESPONSE,
    FILE_CLIENT_ERROR,
    FILE_NOT_FOUND,
    FILE_SERVER_ERROR,
    FILE_REQUEST_TIMEOUT,
    FILE_TOO_LARGE,
    INTERNAL_SERVER_ERROR
    ;

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}
