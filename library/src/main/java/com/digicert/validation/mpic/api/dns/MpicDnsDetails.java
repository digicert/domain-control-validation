package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;

import java.util.List;

/**
 * Represents the details of a DNS validation method for MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the MPIC details, the domain being validated, the DNS records associated with it,
 * and any errors encountered while retrieving the MPIC response
 */
public record MpicDnsDetails(MpicDetails mpicDetails,
                             String domain,
                             List<DnsRecord> dnsRecords,
                             DcvError dcvError) {
}
