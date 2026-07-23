package com.digicert.validation.client.dns;

import com.digicert.validation.enums.DnsType;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 * Represents a DNS record value with its type, name, value, and time-to-live (TTL).
 */
@Data
@AllArgsConstructor
public class DnsValue implements Serializable {
    /** The type of DNS record (e.g., TXT, CNAME, CAA). */
    private DnsType dnsType;
    /** The DNS record name (domain name). */
    private String name;
    /** The DNS record value. */
    private String value;
    /** The time-to-live of the DNS record in seconds. */
    private long ttl;

    /** Creates a new {@code DnsValue} with all fields set to their default values. */
    public DnsValue() {
    }
}