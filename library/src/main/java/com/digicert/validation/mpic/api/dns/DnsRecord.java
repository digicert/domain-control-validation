package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;

public record DnsRecord(DnsType dnsType,
                        String name,
                        String value,
                        long ttl,
                        int flag,
                        String tag) {

    public static Builder builder() {
        return new Builder();
    }

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
