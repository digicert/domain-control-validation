package com.digicert.validation.methods.dns.validate.handlers;

import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class ValidationHandlerHelpers {

    private ValidationHandlerHelpers() {
    }

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
