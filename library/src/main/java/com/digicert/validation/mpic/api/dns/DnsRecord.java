package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;

/**
 * Represents a DNS record used in the MPIC (Multi-Perspective Corroboration) validation process.
 * This record encapsulates the DNS type, name, value, time-to-live (TTL), flag, and tag associated with the DNS record.
 */
public record DnsRecord(DnsType dnsType,
                        String name,
                        String value,
                        long ttl,
                        int flag,
                        String tag) {

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing instances of {@link DnsRecord}.
     * This class provides methods to set each field of the DNS record.
     */
    public static class Builder {
        private DnsType dnsType;
        private String name;
        private String value;
        private long ttl;
        private int flag;
        private String tag;

        public Builder dnsType(DnsType dnsType) {
            this.dnsType = dnsType;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder value(String value) {
            this.value = value;
            return this;
        }

        public Builder ttl(long ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder flag(int flag) {
            this.flag = flag;
            return this;
        }

        public Builder tag(String tag) {
            this.tag = tag;
            return this;
        }

        public DnsRecord build() {
            return new DnsRecord(dnsType, name, value, ttl, flag, tag);
        }
    }
}
