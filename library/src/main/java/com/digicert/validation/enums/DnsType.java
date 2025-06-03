package com.digicert.validation.enums;

import org.xbill.DNS.Type;

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

    /** Delegation Signer record, which is used in DNSSEC to secure the delegation of a DNS zone. */
    DS,

    /** Resource Record Signature, which is used in DNSSEC to provide authenticity and integrity of DNS records. */
    RRSIG;

    public static DnsType fromInt(int type) {
        return switch (type) {
            case Type.A -> A;
            case Type.CAA -> CAA;
            case Type.CNAME -> CNAME;
            case Type.MX -> MX;
            case Type.TXT -> TXT;
            case Type.RRSIG -> RRSIG;
            case Type.DS -> DS;
            default -> throw new IllegalArgumentException("Invalid DNS type: " + type);
        };
    }

}