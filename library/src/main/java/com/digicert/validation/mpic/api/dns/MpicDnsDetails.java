package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;

import java.util.List;

/**
 * Represents the details of a DNS validation method for MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the MPIC details, the domain being validated, the DNS records associated with it,
 * and any errors encountered while retrieving the MPIC response.
 *
 * @param mpicDetails            the MPIC corroboration summary for this DNS validation
 * @param domain                 the domain name being validated
 * @param dnsRecords             the DNS records retrieved during validation
 * @param dcvError               any DCV error encountered during DNS retrieval, or {@code null} if none
 * @param secondaryDnsResponses  the raw secondary agent DNS responses
 */
public record MpicDnsDetails(MpicDetails mpicDetails,
                             String domain,
                             List<DnsRecord> dnsRecords,
                             DcvError dcvError,
                             List<SecondaryDnsResponse> secondaryDnsResponses) {

    /** Backward-compatible constructor that defaults secondary DNS responses to an empty list. */
    public MpicDnsDetails(MpicDetails mpicDetails,
                          String domain,
                          List<DnsRecord> dnsRecords,
                          DcvError dcvError) {
        this(mpicDetails, domain, dnsRecords, dcvError, List.of());
    }
}
