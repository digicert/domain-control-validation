package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;
import lombok.Builder;

/**
 * Represents a DNS record used in the MPIC (Multi-Perspective Corroboration) validation process.
 * This record encapsulates the DNS type, name, value, time-to-live (TTL), flag, and tag associated with the DNS record.
 */
@Builder
public record DnsRecord(DnsType dnsType,
                        String name,
                        String value,
                        long ttl,
                        int flag,
                        String tag) {
}
