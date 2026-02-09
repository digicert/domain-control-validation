package com.digicert.validation.mpic.api;

/**
 * Enum representing the various statuses that can be returned by the MPIC agent.
 * These statuses indicate the result of DNS lookups and file validations.
 */
public enum AgentStatus {
    DNS_LOOKUP_SUCCESS,
    DNS_LOOKUP_BAD_REQUEST,
    DNS_LOOKUP_RECORD_NOT_FOUND,
    DNS_LOOKUP_TEXT_PARSE_EXCEPTION,
    DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION,
    DNS_LOOKUP_DOMAIN_NOT_FOUND,
    DNS_LOOKUP_IO_EXCEPTION,
    DNS_LOOKUP_TIMEOUT,
    DNS_LOOKUP_DNSSEC_FAILURE,

    FILE_SUCCESS,
    FILE_BAD_REQUEST,
    FILE_BAD_RESPONSE,
    FILE_CLIENT_ERROR,
    FILE_NOT_FOUND,
    FILE_SERVER_ERROR,
    FILE_REQUEST_TIMEOUT,
    FILE_TOO_LARGE,

    INTERNAL_SERVER_ERROR
}
