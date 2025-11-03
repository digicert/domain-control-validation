package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Handles DNS validation processes. */
@Slf4j
public class DnsValidationHandler {

    /** The DNS domain label used for validation. */
    final String dnsDomainLabel;

    /** The random value validator used to confirm that a DNS record contains the expected random value. */
    final RandomValueValidator randomValueValidator;

    /** The request token validator used to confirm that a DNS record contains a valid request token. */
    final RequestTokenValidator requestTokenValidator;

    /** The MPIC service used to fetch DNS details. */
    final MpicDnsService mpicDnsService;

    /**
     * Constructs a new DnsValidationHandler with the specified configuration.
     *
     * @param dcvContext context where we can find the necessary dependencies / configuration
     */
    public DnsValidationHandler(DcvContext dcvContext) {
        this.randomValueValidator = dcvContext.get(RandomValueValidator.class);
        this.requestTokenValidator = dcvContext.get(RequestTokenValidator.class);
        this.mpicDnsService = dcvContext.get(MpicDnsService.class);

        this.dnsDomainLabel = dcvContext.getDcvConfiguration().getDnsDomainLabel();
    }

    /**
     * Validates the DNS records based on the provided request.
     * <p>
     * This method performs the DNS validation process based on the given DNS validation request. It fetches the DNS
     * data using the DNS client, validates the DNS records against the provided challenge type, and builds a DNS
     * validation response.
     *
     * @param request the DNS validation request
     * @return the DNS validation response
     */
    public DnsValidationResponse validate(DnsValidationRequest request) {
        switch (request.getChallengeType()) {
            case RANDOM_VALUE -> {
                return performValidationForRandomValue(request);
            }
            case REQUEST_TOKEN -> {
                return performValidationForRequestToken(request);
            }
            default -> throw new IllegalStateException("Unexpected value: " + request.getChallengeType());
        }
    }

    private DnsValidationResponse performValidationForRandomValue(DnsValidationRequest request) {
        // First attempt to validate the request using the domain with the DNS domain label.
        MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(getDomainWithLabel(request), request.getDnsType(), request.getRandomValue());
        ChallengeValidationResponse challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);

        // If the DNS entry with the domain label fails, then we will
        // try validating the request using the domain without the DNS domain label.
        if (challengeValidationResponse.challengeValue().isEmpty()) {
            mpicDnsDetails = mpicDnsService.getDnsDetails(request.getDomain(), request.getDnsType(), request.getRandomValue());
            challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);
        }

        return buildDnsValidationResponse(request.getDomain(), challengeValidationResponse, request.getDnsType(), request.getChallengeType(), mpicDnsDetails.mpicDetails(), mpicDnsDetails.domain());
    }

    private DnsValidationResponse performValidationForRequestToken(DnsValidationRequest request) {
        // Find the request token first in the primary DNS details and then perform the corroborated lookup if found.
        String domainWithLabel = getDomainWithLabel(request);
        ChallengeValidationResponse challengeValidationResponse = getPrimaryChallengeResponse(request, domainWithLabel, request.getDnsType());

        if (challengeValidationResponse.challengeValue().isPresent() && challengeValidationResponse.errors().isEmpty()) {
            // If we found a valid request token in the primary DNS details, perform the corroborated lookup.
            MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(
                    domainWithLabel,
                    request.getDnsType(),
                    challengeValidationResponse.challengeValue().get());
            challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);

            if (challengeValidationResponse.challengeValue().isPresent() && challengeValidationResponse.errors().isEmpty()) {
                return buildDnsValidationResponse(request.getDomain(),
                        challengeValidationResponse,
                        request.getDnsType(),
                        request.getChallengeType(),
                        mpicDnsDetails.mpicDetails(),
                        mpicDnsDetails.domain());
            }
        }

        // If we did not find a valid request token in the DNS details with the domain label, try without the domain label.
        challengeValidationResponse = getPrimaryChallengeResponse(request, request.getDomain(), request.getDnsType());
        if (challengeValidationResponse.challengeValue().isPresent() && challengeValidationResponse.errors().isEmpty()) {
            // If we found a valid request token in the primary DNS details, perform the corroborated lookup.
            MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(request.getDomain(), request.getDnsType(), challengeValidationResponse.challengeValue().get());
            challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);

            if (challengeValidationResponse.challengeValue().isPresent() && challengeValidationResponse.errors().isEmpty()) {
                return buildDnsValidationResponse(request.getDomain(),
                        challengeValidationResponse,
                        request.getDnsType(),
                        request.getChallengeType(),
                        mpicDnsDetails.mpicDetails(),
                        mpicDnsDetails.domain());
            }
        }

        // If we are here, it means we did not find a valid request token in either the DNS details with or without the domain label.
        return buildDnsValidationResponse(request.getDomain(),
                challengeValidationResponse,
                request.getDnsType(),
                request.getChallengeType(),
                null,
                null);
    }

    private ChallengeValidationResponse getPrimaryChallengeResponse(DnsValidationRequest request, String domain, DnsType dnsType) {
        PrimaryDnsResponse primaryDnsDetails = mpicDnsService.getPrimaryDnsDetails(domain, dnsType);
        if (primaryDnsDetails == null || primaryDnsDetails.dnsRecords() == null || primaryDnsDetails.dnsRecords().isEmpty()) {
            DcvError dcvError = mpicDnsService.mapToDcvErrorOrNull(primaryDnsDetails, MpicStatus.VALUE_NOT_FOUND);
            return new ChallengeValidationResponse(Optional.empty(), Set.of(dcvError));
        } else {
            return getChallengeValidationResponse(request, primaryDnsDetails.dnsRecords());
        }
    }

    private ChallengeValidationResponse getChallengeValidationResponse(DnsValidationRequest request, MpicDnsDetails mpicDnsDetails) {
        if (mpicDnsDetails.dcvError() != null) {
            return new ChallengeValidationResponse(Optional.empty(), Set.of(mpicDnsDetails.dcvError()));
        }

        return getChallengeValidationResponse(request, mpicDnsDetails.dnsRecords());
    }

    private ChallengeValidationResponse getChallengeValidationResponse(DnsValidationRequest request, List<DnsRecord> dnsRecords) {
        if (dnsRecords == null || dnsRecords.isEmpty()) {
            return new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        }

        List<String> dnsValues = dnsRecords.stream()
                .map(DnsRecord::value)
                .toList();

        return switch (request.getChallengeType()) {
            case RANDOM_VALUE -> validateRandomValue(dnsValues, request);
            case REQUEST_TOKEN -> validateRequestToken(dnsValues, request);
        };
    }

    /**
     * Validates the DNS records against the supplied random value.
     * <p>
     * This method validates the DNS records found against the random value provided in the DNS validation request. It
     * iterates through the DNS record values and uses the RandomValueValidator to check if any of the record values
     * match the random value. If a match is found, the ChallengeValidationResponse returned will contain the random
     * value; otherwise, it will contain all the errors found while attempting validation.
     *
     * @param recordValues the values of the DNS records
     * @param request the DNS validation request
     * @return the {@link RandomValueValidator} response
     */
    private ChallengeValidationResponse validateRandomValue(List<String> recordValues, DnsValidationRequest request) {
        return recordValues.stream()
                .map(recordValue -> randomValueValidator.validate(request.getRandomValue(), recordValue))
                .reduce(ChallengeValidationResponse::merge)
                .orElse(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)));
    }

    /**
     * Validates the DNS records for the presence of a valid request token.
     * <p>
     * This method iterates through the DNS record values and uses the {@link RequestTokenValidator} with the supplied
     * request token data to check if any of the record values contains a valid request token. If a valid request token
     * is found, the ChallengeValidationResponse returned will contain that valid token; otherwise it will contain all
     * the errors found while attempting validation.
     *
     * @param recordValues the values of the DNS records
     * @param request the DNS validation request
     * @return a {@link ChallengeValidationResponse} containing the first valid request token found or all errors that
     * occurred during the DNS lookups.
     */
    private ChallengeValidationResponse validateRequestToken(List<String> recordValues, DnsValidationRequest request) {
        return recordValues.stream()
                .map(recordValue -> requestTokenValidator.validate(request.getRequestTokenData(), recordValue))
                .reduce(ChallengeValidationResponse::merge)
                .orElse(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)));
    }

    /**
     * Builds a DNS validation response based on the provided parameters.
     * <p>
     * This method constructs a DnsValidationResponse object based on the challenge validator response, DNS data,
     * DNS type, and challenge type. It places the challenge value in the correct place based on the challenge type and
     * includes any errors encountered during the validation process.
     *
     * @param domain
     * @param challengeValidationResponse the token validator response
     * @param dnsType                     the DNS type (CNAME, TXT, or CAA)
     * @param challengeType               the challenge type (RANDOM_VALUE or REQUEST_TOKEN)
     * @param mpicDetails                 the MPIC details
     * @param dnsRecordName               the DNS name used when finding the DNS Details
     * @return the DNS validation response
     */
    DnsValidationResponse buildDnsValidationResponse(String domain,
                                                     ChallengeValidationResponse challengeValidationResponse,
                                                     DnsType dnsType,
                                                     ChallengeType challengeType,
                                                     MpicDetails mpicDetails,
                                                     String dnsRecordName) {
        if (challengeValidationResponse == null) {
            // If the challenge validation response is null, it means there was an error in the DNS lookup
            return new DnsValidationResponse(false,
                    mpicDetails,
                    domain,
                    dnsRecordName,
                    dnsType,
                    null,
                    null,
                    Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        }

        String validRandomValue = null;
        String validRequestToken = null;

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            validRandomValue = challengeValidationResponse.challengeValue().orElse(null);
        } else {
            validRequestToken = challengeValidationResponse.challengeValue().orElse(null);
        }

        return new DnsValidationResponse(challengeValidationResponse.challengeValue().isPresent(),
                mpicDetails,
                domain,
                dnsRecordName,
                dnsType,
                validRandomValue,
                validRequestToken,
                challengeValidationResponse.errors());
    }

    private String getDomainWithLabel(DnsValidationRequest request) {
        return normalizeDomainLabel(getDomainLabel(request)) + request.getDomain();
    }

    private String getDomainLabel(DnsValidationRequest request) {
        if (request.getDomainLabel() != null && !request.getDomainLabel().isEmpty()) {
            return request.getDomainLabel();
        } else {
            return dnsDomainLabel;
        }
    }

    private String normalizeDomainLabel(String domainWithLabel) {
        if (domainWithLabel.endsWith(".")) {
            return domainWithLabel;
        } else {
            return domainWithLabel + ".";
        }
    }
}