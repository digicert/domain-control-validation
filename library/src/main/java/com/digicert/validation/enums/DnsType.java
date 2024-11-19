package com.digicert.validation.enums;

/**
 * Enum representing the DNS record types that can be requested.
 * <p>
 * DNS records are essential components of the Domain Name System (DNS), which is responsible for translating human-readable domain names into IP addresses.
 * Each DNS record type serves a specific purpose and provides different types of information about a domain.
 */
public enum DnsType {
    /** Alias of one name to another. */
    CNAME,

    /** Specifies freeform supplemental text data. */
    TXT,

    /** Specifies which certificate authorities (CAs) are allowed to issue certificates for the domain. */
    CAA,

    /** Address record, which is used to map hostnames to their IP address. */
    A,

    /** Email exchange record, which points to the IP Addresses of a domain's mail server */
    MX,
}