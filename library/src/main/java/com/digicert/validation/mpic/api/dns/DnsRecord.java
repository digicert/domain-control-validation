package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;
import lombok.Builder;

/**
 * Represents a DNS record used in the MPIC (Multi-Perspective Corroboration) validation process.
 * This record encapsulates the DNS type, name, value, time-to-live (TTL), flag, and tag associated with the DNS record.
 *
 * @param dnsType  the type of DNS record (e.g., TXT, CNAME, CAA)
 * @param name     the DNS record name (domain name)
 * @param value    the DNS record value
 * @param ttl      the time-to-live of the DNS record in seconds
 * @param flag     the flag field, used primarily for CAA records
 * @param tag      the tag field, used primarily for CAA records
 */
@Builder
public record DnsRecord(DnsType dnsType,
                        String name,
                        String value,
                        long ttl,
                        int flag,
                        String tag) {
}
