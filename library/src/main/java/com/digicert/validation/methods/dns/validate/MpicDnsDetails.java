package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.api.dns.DnsRecord;

import java.util.List;

public record MpicDnsDetails(MpicDetails mpicDetails,
                             String domain,
                             List<DnsRecord> dnsRecords,
                             DcvError dcvError) {
}
