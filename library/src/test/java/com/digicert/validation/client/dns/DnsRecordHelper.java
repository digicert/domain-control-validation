package com.digicert.validation.client.dns;

import com.digicert.validation.enums.DnsType;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;

public class DnsRecordHelper {
    public static Record getDnsRecordFromType(String domain, DnsType dnsType) throws TextParseException, UnknownHostException {
        String zoneName = !domain.endsWith(".") ? domain + "." : domain;

        return switch (dnsType) {
            case A -> new ARecord(Name.fromString(zoneName), DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));
            case TXT -> new TXTRecord(Name.fromString(zoneName), DClass.IN, 3600, List.of("testValue", "testValue2"));
            case CNAME -> new CNAMERecord(Name.fromString(zoneName), DClass.IN, 3600, Name.fromString("http://cname.example.com."));
            case CAA -> new CAARecord(Name.fromString(zoneName), DClass.IN, 3600, 0, "issue", "letsencrypt.org");
            case MX -> new MXRecord(Name.fromString(zoneName), DClass.IN, 3600, 0, Name.fromString("http://mx.example.com."));
            case RRSIG -> new RRSIGRecord(Name.fromString(zoneName), DClass.IN, 3600, 0, 0, 0, Instant.now(), Instant.now(), 0, Name.fromString("http://example.com."), new byte[]{});
            case DS -> new DSRecord(Name.fromString(zoneName), DClass.IN, 3600, 0, 0, 0, new byte[]{});
        };
    }
}
