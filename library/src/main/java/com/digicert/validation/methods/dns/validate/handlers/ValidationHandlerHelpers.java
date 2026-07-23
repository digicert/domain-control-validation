package com.digicert.validation.methods.dns.validate.handlers;

import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Utility methods shared across DNS validation handlers.
 */
public final class ValidationHandlerHelpers {

    private ValidationHandlerHelpers() {
    }

    /**
     * Checks the given MPIC DNS details for common errors (DCV error or empty records).
     *
     * @param mpicDnsDetails the MPIC DNS details to inspect
     * @return an {@link Optional} containing a {@link ChallengeValidationResponse} with the error if present,
     *         or {@link Optional#empty()} if no common error was detected
     */
    public static Optional<ChallengeValidationResponse> checkForCommonErrors(MpicDnsDetails mpicDnsDetails){
        if (mpicDnsDetails.dcvError() != null) {
            return Optional.of(new ChallengeValidationResponse(Optional.empty(), Set.of(mpicDnsDetails.dcvError())));
        }

        List<DnsRecord> dnsRecords = mpicDnsDetails.dnsRecords();
        if (dnsRecords == null || dnsRecords.isEmpty()) {
            return Optional.of(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)));
        }
        return Optional.empty();
    }

    /**
     * Constructs the fully-qualified DNS name to query by prepending the domain label to the request's domain.
     *
     * @param request            the DNS validation request containing the domain and optional domain label
     * @param defaultDomainLabel the label to use when the request does not specify one
     * @return the domain name with the label prepended (e.g., {@code _dv.example.com})
     */
    public static String getDomainWithLabel(DnsValidationRequest request, String defaultDomainLabel) {
        return addTrailingDot(getDomainLabel(request, defaultDomainLabel)) + request.getDomain();
    }

    private static String getDomainLabel(DnsValidationRequest request, String defaultDomainLabel) {
        if (request.getDomainLabel() != null && !request.getDomainLabel().isEmpty()) {
            return request.getDomainLabel();
        }
        return defaultDomainLabel;
    }

    private static String addTrailingDot(String domainLabel) {
        if (domainLabel.endsWith(".")) {
            return domainLabel;
        }
        return domainLabel + ".";
    }

}
