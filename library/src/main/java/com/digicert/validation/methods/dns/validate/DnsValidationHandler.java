package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.secrets.RandomValueValidator;
import com.digicert.validation.secrets.TokenValidator;
import com.digicert.validation.secrets.ChallengeValidationResponse;
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

    /** Validator for random value secrets. */
    final RandomValueValidator randomValueValidator;

    /** Validator for token secrets. */
    final TokenValidator tokenValidator;

    /** The DNS client used to fetch DNS data. */
    final DnsClient dnsClient;

    /**
     * Constructs a new DnsValidationHandler with the specified configuration.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public DnsValidationHandler(DcvContext dcvContext) {
        this.randomValueValidator = dcvContext.get(RandomValueValidator.class);
        this.tokenValidator = dcvContext.get(TokenValidator.class);
        this.dnsClient = dcvContext.get(DnsClient.class);

        this.dnsDomainLabel = dcvContext.getDcvConfiguration().getDnsDomainLabel();
    }

    /**
     * Validates the DNS records based on the provided request.
     * <p>
     * This method performs the DNS validation process based on the given DNS validation request. It fetches the DNS
     * data using the DNS client, validates the DNS records against the provided secret type, and builds a DNS validation
     * response.
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
     * Validates the random value secret against the DNS records.
     * <p>
     * This method validates the random value secret provided in the DNS validation request against the DNS records.
     * It iterates through the DNS record values and uses the RandomValueValidator to check if the random value matches
     * any of the record values. If a match is found, a successful TokenValidatorResponse is returned; otherwise, an
     * error response is generated.
     *
     * @param recordValues the values of the DNS records
     * @param request      the DNS validation request
     * @return the token validator response
     */
    private ChallengeValidationResponse validateRandomValue(List<String> recordValues, DnsValidationRequest request) {
        return recordValues.stream()
                .map(recordValue -> randomValueValidator.validate(request.getRandomValue(), recordValue))
                .filter(tr -> tr.errors().isEmpty() && tr.token().isPresent())
                .findFirst()
                .orElse(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.RANDOM_VALUE_NOT_FOUND)));
    }

    /**
     * Validates the request token against the DNS records.
     * <p>
     * This method validates the request token provided in the DNS validation request against the DNS records. It
     * iterates through the DNS record values and uses the TokenValidator to check if the token matches any of the
     * record values. If a match is found, a successful TokenValidatorResponse is returned; otherwise, an error response
     * is generated.
     *
     * @param recordValues the values of the DNS records
     * @param request      the DNS validation request
     * @return the token validator response
     */
    private ChallengeValidationResponse validateRequestToken(List<String> recordValues, DnsValidationRequest request) {
        return recordValues.stream()
                .map(recordValue -> tokenValidator.validate(request.getTokenKey(), request.getTokenValue(), recordValue))
                .findFirst()
                .orElse(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.TOKEN_ERROR_NOT_FOUND)));
    }

    /**
     * Builds a DNS validation response based on the provided parameters.
     * <p>
     * This method constructs a DnsValidationResponse object based on the token validator response, DNS data, DNS type,
     * and secret type. It determines the validity of the random value or token and includes any errors encountered
     * during the validation process.
     *
     * @param challengeValidationResponse the token validator response
     * @param dnsData                the DNS data
     * @param dnsType                the DNS type
     * @param challengeType             the secret type
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
        String validToken = null;

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            validRandomValue = challengeValidationResponse.token().orElse(null);
        } else {
            validToken = challengeValidationResponse.token().orElse(null);
        }

        return new DnsValidationResponse(challengeValidationResponse.token().isPresent(), dnsData.serverWithData(), dnsData.domain(),
                dnsType, validRandomValue, validToken, challengeValidationResponse.errors());
    }

    /**
     * Retrieves the string value of a DNS record based on its type.
     * <p>
     * This method extracts the string value from a DNS record based on the specified DNS type. It supports different
     * types of DNS records, such as CNAME, TXT, and CAA, and returns the corresponding string representation of the
     * record value.
     *
     * @param dnsRecord the DNS record
     * @param type      the type of DNS record
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