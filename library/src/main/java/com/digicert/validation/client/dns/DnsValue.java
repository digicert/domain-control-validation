package com.digicert.validation.client.dns;

import com.digicert.validation.enums.DnsType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Represents a DNS record value with its type, name, value, and time-to-live (TTL).
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DnsValue implements Serializable {
    private DnsType dnsType;
    private String name;
    private String value;
    private long ttl;
}