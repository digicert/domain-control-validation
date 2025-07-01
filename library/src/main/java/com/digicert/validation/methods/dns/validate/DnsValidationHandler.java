package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
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

        // First attempt to validate the request using the domain with the DNS domain label.
        MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(dnsDomainLabel + request.getDomain(), request.getDnsType());
        ChallengeValidationResponse challengeValidationResponse = null;
        if (mpicDnsDetails.dcvError() == null) {
            challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);
        }

        // If the DNS entry with the domain label fails, then we will
        // try validating the request using the domain without the DNS domain label.
        if (challengeValidationResponse == null || challengeValidationResponse.challengeValue().isEmpty()) {
            mpicDnsDetails = mpicDnsService.getDnsDetails(request.getDomain(), request.getDnsType());
            if (mpicDnsDetails.dcvError() == null) {
                // If the domain without the DNS domain label is valid, validate it.
                challengeValidationResponse = getChallengeValidationResponse(request, mpicDnsDetails);
            }
        }

        return buildDnsValidationResponse(request.getDomain(), challengeValidationResponse, mpicDnsDetails, request.getDnsType(), request.getChallengeType());
    }

    private ChallengeValidationResponse getChallengeValidationResponse(DnsValidationRequest request, MpicDnsDetails mpicDnsDetails) {
        List<String> dnsValues = mpicDnsDetails.dnsRecords().stream()
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
     * @param mpicDnsDetails              the DNS data
     * @param dnsType                     the DNS type (CNAME, TXT, or CAA)
     * @param challengeType               the challenge type (RANDOM_VALUE or REQUEST_TOKEN)
     * @return the DNS validation response
     */
    DnsValidationResponse buildDnsValidationResponse(String domain,
                                                     ChallengeValidationResponse challengeValidationResponse,
                                                     MpicDnsDetails mpicDnsDetails,
                                                     DnsType dnsType,
                                                     ChallengeType challengeType) {
        if (challengeValidationResponse == null) {
            // If the challenge validation response is null, it means there was an error in the DNS lookup
            DcvError dcvError = mpicDnsDetails.dcvError() == null ? DcvError.DNS_LOOKUP_RECORD_NOT_FOUND : mpicDnsDetails.dcvError();
            return new DnsValidationResponse(false,
                    mpicDnsDetails.mpicDetails(),
                    domain,
                    mpicDnsDetails.domain(),
                    dnsType,
                    null,
                    null,
                    Set.of(dcvError));
        }

        String validRandomValue = null;
        String validRequestToken = null;

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            validRandomValue = challengeValidationResponse.challengeValue().orElse(null);
        } else {
            validRequestToken = challengeValidationResponse.challengeValue().orElse(null);
        }

        return new DnsValidationResponse(challengeValidationResponse.challengeValue().isPresent(),
                mpicDnsDetails.mpicDetails(),
                domain,
                mpicDnsDetails.domain(),
                dnsType,
                validRandomValue,
                validRequestToken,
                challengeValidationResponse.errors());
    }
}