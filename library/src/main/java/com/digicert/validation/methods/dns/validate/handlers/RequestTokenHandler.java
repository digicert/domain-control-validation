package com.digicert.validation.methods.dns.validate.handlers;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.utils.StateValidationUtils;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.digicert.validation.methods.dns.validate.handlers.ValidationHandlerHelpers.checkForCommonErrors;

/**
 * Handles DNS validation requests for request-token challenge values.
 *
 * <p>The handler first checks the labeled DNS name, and if no valid token is found,
 * retries on the base domain. When a candidate token is found in primary DNS data,
 * it is validated again using corroborated MPIC responses.
 */
public final class RequestTokenHandler {

    private final String dnsDomainLabel;
    private final MpicDnsService mpicDnsService;
    private final RequestTokenValidator requestTokenValidator;

    public RequestTokenHandler(DcvContext dcvContext) {
        this.dnsDomainLabel = dcvContext.getDcvConfiguration().getDnsDomainLabel();
        mpicDnsService = dcvContext.get(MpicDnsService.class);
        requestTokenValidator = dcvContext.get(RequestTokenValidator.class);
    }

    /**
     * Validates a request-token challenge against DNS records.
     *
     * @param request the DNS validation request
     * @return DNS validation result with errors from all attempted lookups
     * @throws DcvException when request state or required token input is invalid
     */
    public DnsValidationResponse validate(DnsValidationRequest request) throws DcvException {
        verifyRequest(request);
        var responseBuilder = DnsValidationResponse.builder()
                                      .domain(request.getDomain())
                                      .dnsType(request.getDnsType());
        // Find the request token first in the primary DNS details and then perform the corroborated lookup if found.
        String domainWithLabel = ValidationHandlerHelpers.getDomainWithLabel(request, dnsDomainLabel);
        ChallengeValidationResponse challengeResponseWithLabel = getPrimaryChallengeResponse(
                request,
                domainWithLabel,
                request.getDnsType());
        if (valueIsPresentAndNoErrorsWereFound(challengeResponseWithLabel)) {
            // A candidate token was found in primary DNS details; corroborate via MPIC lookup.
            MpicDnsDetails mpicDnsDetails = this.mpicDnsService.getDnsDetails(
                    domainWithLabel,
                    request.getDnsType(),
                    challengeResponseWithLabel.challengeValue().get());
            challengeResponseWithLabel = getChallengeResponse(request, mpicDnsDetails);

            if (valueIsPresentAndNoErrorsWereFound(challengeResponseWithLabel)) {
                return responseBuilder
                               .isValid(true)
                               .mpicDetails(mpicDnsDetails.mpicDetails())
                               .dnsRecordName(mpicDnsDetails.domain())
                               .validRequestToken(challengeResponseWithLabel.challengeValue().orElse(null))
                               .build();
            }
        }


        // If labeled lookup is not valid, repeat the process on the base domain.
        ChallengeValidationResponse challengeResponseWithoutLabel = getPrimaryChallengeResponse(request, request.getDomain(), request.getDnsType());
        if (valueIsPresentAndNoErrorsWereFound(challengeResponseWithoutLabel)) {
            // If we found a valid request token in the primary DNS details, perform the corroborated lookup.
            MpicDnsDetails mpicDnsDetails = this.mpicDnsService.getDnsDetails(request.getDomain(), request.getDnsType(), challengeResponseWithoutLabel.challengeValue().get());
            challengeResponseWithoutLabel = getChallengeResponse(request, mpicDnsDetails);

            if (valueIsPresentAndNoErrorsWereFound(challengeResponseWithoutLabel)) {
                // A valid request token was found using the base domain name.
                return responseBuilder.isValid(true)
                               .mpicDetails(mpicDnsDetails.mpicDetails())
                               .dnsRecordName(mpicDnsDetails.domain())
                               .validRequestToken(challengeResponseWithoutLabel.challengeValue().orElse(null))
                               .build();
            }
        }
        // Merge both lookup paths so we keep the complete set of validation errors.
        ChallengeValidationResponse challengeValidationResponse = challengeResponseWithLabel.merge(challengeResponseWithoutLabel);
        return new DnsValidationResponse(challengeValidationResponse.challengeValue().isPresent(),
                null,
                request.getDomain(),
                null,
                request.getDnsType(),
                null,
                challengeValidationResponse.challengeValue().orElse(null),
                null,
                challengeValidationResponse.errors());
    }

    private static boolean valueIsPresentAndNoErrorsWereFound(ChallengeValidationResponse challengeResponseWithoutLabel) {
        return challengeResponseWithoutLabel.challengeValue().isPresent() && challengeResponseWithoutLabel.errors().isEmpty();
    }

    private void verifyRequest(DnsValidationRequest request) throws DcvException {
        StateValidationUtils.verifyValidationState(request.getValidationState(), DcvMethod.BR_3_2_2_4_7);
        if (request.getRequestTokenData() == null) {
            throw new InputException(DcvError.REQUEST_TOKEN_DATA_REQUIRED);
        }
    }


    /**
     * Reads primary DNS responses and validates all record values as request-token candidates.
     *
     * @param request request containing request-token validation data
     * @param domain DNS name to query
     * @param dnsType record type to query
     * @return merged validation response across all primary DNS record values
     */
    public ChallengeValidationResponse getPrimaryChallengeResponse(DnsValidationRequest request,
                                                                   String domain,
                                                                   DnsType dnsType) {
        PrimaryDnsResponse primaryDnsDetails = this.mpicDnsService.getPrimaryDnsDetails(domain, dnsType);
        if (primaryDnsDetails == null || primaryDnsDetails.dnsRecords() == null || primaryDnsDetails.dnsRecords().isEmpty()) {
            DcvError dcvError = this.mpicDnsService.mapToDcvErrorOrNull(primaryDnsDetails, MpicStatus.VALUE_NOT_FOUND);
            return new ChallengeValidationResponse(Optional.empty(), Set.of(dcvError));
        }
        List<DnsRecord> dnsRecords = primaryDnsDetails.dnsRecords();

        List<String> dnsValues = dnsRecords.stream().map(DnsRecord::value).toList();
        return validateRequestToken(dnsValues, request);
    }

    private ChallengeValidationResponse getChallengeResponse(DnsValidationRequest request, MpicDnsDetails mpicDnsDetails) {
        return checkForCommonErrors(mpicDnsDetails)
                       .orElseGet(() -> validateRequestToken(mpicDnsDetails.dnsRecords().stream().map(DnsRecord::value).toList(), request)
        );
    }

    /**
     * Validates DNS record values until a valid request token is found, or merges all errors.
     *
     * @param recordValues record values from one DNS lookup
     * @param request request containing request-token validation payload
     * @return a merged response containing either a valid token or accumulated errors
     */
    public ChallengeValidationResponse validateRequestToken(List<String> recordValues,
                                                            DnsValidationRequest request) {
        return recordValues.stream()
                       .map(recordValue -> this.requestTokenValidator.validate(request.getRequestTokenData(), recordValue))
                       .reduce(ChallengeValidationResponse::merge)
                       .orElseGet(() -> new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)));
    }
}
