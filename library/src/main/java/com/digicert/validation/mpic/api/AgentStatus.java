package com.digicert.validation.mpic.api;

/**
 * Enum representing the various statuses that can be returned by the MPIC agent.
 * These statuses indicate the result of DNS lookups and file validations.
 */
public enum AgentStatus {
    /** DNS lookup completed successfully. */
    DNS_LOOKUP_SUCCESS,
    /** The DNS lookup request was malformed or invalid. */
    DNS_LOOKUP_BAD_REQUEST,
    /** The requested DNS record was not found. */
    DNS_LOOKUP_RECORD_NOT_FOUND,
    /** An exception occurred while parsing the DNS text record. */
    DNS_LOOKUP_TEXT_PARSE_EXCEPTION,
    /** The DNS host could not be resolved (unknown host). */
    DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION,
    /** The domain was not found during DNS lookup. */
    DNS_LOOKUP_DOMAIN_NOT_FOUND,
    /** An I/O exception occurred during the DNS lookup. */
    DNS_LOOKUP_IO_EXCEPTION,
    /** The DNS lookup timed out before a response was received. */
    DNS_LOOKUP_TIMEOUT,
    /** DNSSEC validation failed for the DNS response. */
    DNS_LOOKUP_DNSSEC_FAILURE,

    /** The file was fetched successfully. */
    FILE_SUCCESS,
    /** The file request was malformed or invalid. */
    FILE_BAD_REQUEST,
    /** The server returned a bad or unreadable response for the file request. */
    FILE_BAD_RESPONSE,
    /** A client-side error occurred while fetching the file. */
    FILE_CLIENT_ERROR,
    /** The requested file was not found on the server. */
    FILE_NOT_FOUND,
    /** The server returned a server-side error while fetching the file. */
    FILE_SERVER_ERROR,
    /** The file request timed out before a response was received. */
    FILE_REQUEST_TIMEOUT,
    /** The response file was too large to process. */
    FILE_TOO_LARGE,

    /** An unexpected internal server error occurred. */
    INTERNAL_SERVER_ERROR
}
