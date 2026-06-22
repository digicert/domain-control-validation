package com.digicert.validation.methods.dns.validate.handlers;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.random.RandomValueVerifier;
import com.digicert.validation.utils.StateValidationUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Handles DNS validation requests for random-value challenge values.
 *
 * <p>The handler validates the labeled DNS name first, then retries on the base
 * domain and merges results so callers receive all relevant lookup errors.
 */
public final class RandomValueHandler {

    private final MpicDnsService mpicDnsService;
    private final String dnsDomainLabel;
    private final RandomValueValidator randomValueValidator;
    private final RandomValueVerifier randomValueVerifier;

    public RandomValueHandler(DcvContext dcvContext) {
        mpicDnsService = dcvContext.get(MpicDnsService.class);
        dnsDomainLabel = dcvContext.getDcvConfiguration().getDnsDomainLabel();
        randomValueValidator = dcvContext.get(RandomValueValidator.class);
        randomValueVerifier = dcvContext.get(RandomValueVerifier.class);
    }

    /**
     * Validates a random-value challenge against DNS records.
     *
     * @param request DNS validation request
     * @return DNS validation response containing matched random value when present
     * @throws DcvException when state or random value input is invalid
     */
    public DnsValidationResponse validate(DnsValidationRequest request) throws DcvException {
        verifyRequest(request);
        // First attempt to validate the request using the domain with the DNS domain label.
        MpicDnsDetails mpicDnsDetails = this.mpicDnsService.getDnsDetails(ValidationHandlerHelpers.getDomainWithLabel(request, this.dnsDomainLabel),
                request.getDnsType(),
                request.getRandomValue());

        ChallengeValidationResponse challengeResponseWithLabel = getChallengeResponse(request, mpicDnsDetails);

        if (challengeResponseWithLabel.challengeValue().isPresent()) {
            // If we found a valid random value in the DNS entry with the domain label, return the response.
            return new DnsValidationResponse(true,
                    mpicDnsDetails.mpicDetails(),
                    request.getDomain(),
                    mpicDnsDetails.domain(),
                    request.getDnsType(),
                    challengeResponseWithLabel.challengeValue().orElse(null),
                    null,
                    null,
                    challengeResponseWithLabel.errors());
        }

        // The labeled lookup did not validate, so retry against the base domain name.
        mpicDnsDetails = this.mpicDnsService.getDnsDetails(request.getDomain(), request.getDnsType(), request.getRandomValue());
        ChallengeValidationResponse challengeResponseWithoutLabel = getChallengeResponse(request, mpicDnsDetails);

        // Merge both challenge responses so callers receive all discovered errors.
        ChallengeValidationResponse mergedChallenges = challengeResponseWithLabel.merge(challengeResponseWithoutLabel);

        return new DnsValidationResponse(mergedChallenges.challengeValue().isPresent(),
                mpicDnsDetails.mpicDetails(),
                request.getDomain(),
                mpicDnsDetails.domain(),
                request.getDnsType(),
                mergedChallenges.challengeValue().orElse(null),
                null,
                null,
                mergedChallenges.errors());
    }

    private void verifyRequest(DnsValidationRequest request) throws DcvException {
        StateValidationUtils.verifyValidationState(request.getValidationState(), DcvMethod.BR_3_2_2_4_7);
        Instant instant = request.getValidationState().prepareTime();
        randomValueVerifier.verifyRandomValue(request.getRandomValue(), instant);
    }


    private ChallengeValidationResponse getChallengeResponse(DnsValidationRequest request, MpicDnsDetails mpicDnsDetails) {
        return ValidationHandlerHelpers.checkForCommonErrors(mpicDnsDetails)
                       .orElseGet(() -> validateRandomValue(mpicDnsDetails.dnsRecords().stream().map(DnsRecord::value).toList(), request));
    }

    /**
     * Validates DNS record values for a matching random value.
     *
     * @param recordValues DNS record values returned by lookup
     * @param request      DNS validation request containing expected random value
     * @return merged validation response containing the first valid value or all errors
     */
    public ChallengeValidationResponse validateRandomValue(List<String> recordValues, DnsValidationRequest request) {
        return recordValues.stream()
                       .map(recordValue -> this.randomValueValidator.validate(request.getRandomValue(), recordValue))
                       .reduce(ChallengeValidationResponse::merge)
                       .orElse(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)));
    }
}
