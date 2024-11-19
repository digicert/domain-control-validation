package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;

import java.util.Arrays;
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

    /** The DNS client used to fetch DNS data. */
    final DnsClient dnsClient;

    /**
     * Constructs a new DnsValidationHandler with the specified configuration.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public DnsValidationHandler(DcvContext dcvContext) {
        this.randomValueValidator = dcvContext.get(RandomValueValidator.class);
        this.requestTokenValidator = dcvContext.get(RequestTokenValidator.class);
        this.dnsClient = dcvContext.get(DnsClient.class);

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

        List<String> lookupNames = Arrays.asList(dnsDomainLabel + request.getDomain(), request.getDomain());
        DnsData dnsData = dnsClient.getDnsData(lookupNames, request.getDnsType());

        List<String> recordValues = dnsData.records().stream()
                .map(dnsRecord -> getDnsRecordStringValue(dnsRecord, request.getDnsType()))
                .toList();

        ChallengeValidationResponse challengeValidationResponse = null;

        switch (request.getChallengeType()) {
            case RANDOM_VALUE -> challengeValidationResponse = validateRandomValue(recordValues, request);
            case REQUEST_TOKEN -> challengeValidationResponse = validateRequestToken(recordValues, request);
        }

        return buildDnsValidationResponse(challengeValidationResponse, dnsData, request.getDnsType(), request.getChallengeType());
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
     * @param challengeValidationResponse the token validator response
     * @param dnsData the DNS data
     * @param dnsType the DNS type (CNAME, TXT, or CAA)
     * @param challengeType the challenge type (RANDOM_VALUE or REQUEST_TOKEN)
     * @return the DNS validation response
     */
    DnsValidationResponse buildDnsValidationResponse(ChallengeValidationResponse challengeValidationResponse,
                                                     DnsData dnsData,
                                                     DnsType dnsType,
                                                     ChallengeType challengeType) {
        if (challengeValidationResponse == null) {
            return new DnsValidationResponse(false, dnsData.serverWithData(), dnsData.domain(), dnsType,
                    null, null, Set.of());
        }

        String validRandomValue = null;
        String validRequestToken = null;

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            validRandomValue = challengeValidationResponse.challengeValue().orElse(null);
        } else {
            validRequestToken = challengeValidationResponse.challengeValue().orElse(null);
        }

        return new DnsValidationResponse(challengeValidationResponse.challengeValue().isPresent(),
                dnsData.serverWithData(), dnsData.domain(), dnsType, validRandomValue, validRequestToken,
                challengeValidationResponse.errors());
    }

    /**
     * Retrieves the string value of a DNS record based on its type.
     * <p>
     * This method extracts the string value from a DNS record based on the specified DNS type. It supports different
     * types of DNS records, such as CNAME, TXT, and CAA, and returns the corresponding string representation of the
     * record value.
     *
     * @param dnsRecord the DNS record
     * @param type the type of DNS record
     * @return the string value of the DNS record
     */
    String getDnsRecordStringValue(Record dnsRecord, DnsType type) {
        return switch (type) {
            case CNAME -> ((CNAMERecord) dnsRecord).getTarget().toString();
            case TXT -> String.join(System.lineSeparator(), ((TXTRecord) dnsRecord).getStrings());
            case CAA -> ((CAARecord) dnsRecord).getValue();
            default -> throw new IllegalStateException("Unexpected value: " + type);
        };
    }
}