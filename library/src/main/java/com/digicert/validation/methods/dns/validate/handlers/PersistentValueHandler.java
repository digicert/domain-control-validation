package com.digicert.validation.methods.dns.validate.handlers;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.methods.dns.validate.PersistentTxtResponse;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import com.digicert.validation.utils.MpicCorroborationEvaluator;
import com.digicert.validation.utils.StateValidationUtils;
import com.digicert.validation.utils.issueValue.IssueValueParser;
import com.digicert.validation.utils.issueValue.ParsedIssueValue;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Handles DNS validation requests for the persistent-value challenge type.
 *
 * <p>The handler looks up TXT records under the persistent label, parses candidate
 * issue-value records, validates issuer/account/persistUntil fields, and then applies
 * MPIC corroboration rules across secondary DNS responses.
 */
public final class PersistentValueHandler {

    /**
     * Prefix used for persistent TXT DNS lookups.
     */
    public static final String PERSISTENT_DNS_LABEL = "_validation-persist.";
    /** Issue-value parameter key for account URI. */
    public static final String ACCOUNT_URI_KEY = "accounturi";
    /** Issue-value parameter key for expiration timestamp in epoch seconds. */
    public static final String PERSIST_UNTIL_KEY = "persistUntil";
    private final MpicDnsService mpicDnsService;
    private final Set<String> allowedIssuerDomains;


    public PersistentValueHandler(DcvContext dcvContext) {
        this.mpicDnsService = dcvContext.get(MpicDnsService.class);
        this.allowedIssuerDomains = dcvContext.getDcvConfiguration().getAllowedIssuerDomains();
    }

    /**
     * Validates a persistent-value DNS challenge.
     *
     * <p>The primary response is parsed first. If primary validation fails, the primary
     * errors are returned directly. If primary validation succeeds, each secondary response
     * is evaluated and MPIC corroboration is calculated from the secondary results.
     *
     * @param request DNS validation request
     * @return DNS validation response including parsed persistent TXT details when available
     * @throws DcvException when request state or required inputs are invalid
     * @throws IllegalStateException when no issuer domains have been provided to the handler.
     */
    public DnsValidationResponse validate(DnsValidationRequest request) throws DcvException {
        if (this.allowedIssuerDomains.isEmpty()) {
            throw new IllegalStateException("Allowed issuer domains list is empty");
        }
        verifyRequest(request);
        // For persistent values, lookups are always performed at the _validation-persist label.
        String domainWithPersistLabel = PERSISTENT_DNS_LABEL + request.getDomain();
        MpicDnsDetails mpicDnsDetails = this.mpicDnsService.getDnsDetails(domainWithPersistLabel, DnsType.TXT, request.getAccountUri());
        Optional<ChallengeValidationResponse> commonErrors = ValidationHandlerHelpers.checkForCommonErrors(mpicDnsDetails);
        if (commonErrors.isPresent()) {
            return DnsValidationResponse.builder()
                           .isValid(false)
                           .errors(commonErrors.get().errors())
                           .dnsType(DnsType.TXT)
                           .mpicDetails(getMpicDetails(mpicDnsDetails, false, new HashMap<>()))
                           .dnsRecordName(domainWithPersistLabel)
                           .build();
        }

        List<DnsRecord> dnsRecords = mpicDnsDetails.dnsRecords();
        Optional<ParsedIssueValue> parsedPrimaryRecord = findAndParseMostValidPersistentRecord(dnsRecords, request.getAccountUri());
        Set<DcvError> primaryRecordErrors = parsedPrimaryRecord.map(ParsedIssueValue::dcvErrors)
                                                    .orElse(Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        if (!primaryRecordErrors.isEmpty()) {
            // Primary lookup must be valid before corroboration can proceed.
            return DnsValidationResponse.builder()
                           .isValid(false)
                           .errors(primaryRecordErrors)
                           .dnsType(DnsType.TXT)
                           .mpicDetails(getMpicDetails(mpicDnsDetails, false, new HashMap<>())).dnsRecordName(domainWithPersistLabel)
                           .persistentTxtResponse(parsedPrimaryRecord.map(PersistentValueHandler::buildTxtResponse).orElse(null))
                           .build();
        }
        // Evaluate each secondary response against the same parsing/validation rules.
        HashMap<SecondaryDnsResponse, Set<DcvError>> evaluatedSecondaryResponses = mpicDnsDetails.secondaryDnsResponses().stream().collect(HashMap::new, (map, res) -> {
            var parsed = findAndParseMostValidPersistentRecord(res.dnsRecords(), request.getAccountUri());
            Set<DcvError> errors = parsed.map(ParsedIssueValue::dcvErrors)
                                           .orElse(Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
            map.put(res, errors);
        }, HashMap::putAll);

        List<String> corroboratingAgentRIRs = evaluatedSecondaryResponses.entrySet().stream().filter(entry -> entry.getValue().isEmpty()).map(Map.Entry::getKey).map(SecondaryDnsResponse::agentRIR).toList();

        boolean corroborates = MpicCorroborationEvaluator.corroborates(
                mpicDnsDetails.secondaryDnsResponses().size(),
                corroboratingAgentRIRs.size(),
                Set.copyOf(corroboratingAgentRIRs).size());

        Set<DcvError> aggregatedErrors = evaluatedSecondaryResponses.values().stream()
                                                   .flatMap(Collection::stream)
                                                   .collect(Collectors.toSet());
        if (!corroborates && aggregatedErrors.isEmpty()) {
            aggregatedErrors.add(DcvError.MPIC_CORROBORATION_ERROR);
        }

        // Return success only when MPIC corroboration thresholds are met.
        return DnsValidationResponse.builder()
                       .isValid(corroborates)
                       .mpicDetails(getMpicDetails(mpicDnsDetails, corroborates, evaluatedSecondaryResponses))
                       .domain(request.getDomain())
                       .dnsRecordName(domainWithPersistLabel)
                       .dnsType(request.getDnsType())
                       .persistentTxtResponse(parsedPrimaryRecord.map(PersistentValueHandler::buildTxtResponse).orElse(null))
                       .errors(aggregatedErrors)
                       .build();
    }

    private void verifyRequest(DnsValidationRequest request) throws DcvException {
        StateValidationUtils.verifyValidationState(request.getValidationState(), DcvMethod.BR_3_2_2_4_22);

        if (request.getDnsType() != DnsType.TXT) {
            throw new InputException(DcvError.INVALID_DNS_TYPE);
        }

        if (request.getAccountUri() == null || request.getAccountUri().isBlank()) {
            throw new InputException(DcvError.ACCOUNT_URI_REQUIRED);
        }
        verifyUri(request.getAccountUri());
    }

    private void verifyUri(String value) throws InputException {
        try {
            new URI(value);
        } catch (URISyntaxException e) {
            throw new InputException(DcvError.INVALID_ACCOUNT_URI, e);
        }
    }

    private static MpicDetails getMpicDetails(MpicDnsDetails mpicDnsDetails, boolean corroborated, HashMap<SecondaryDnsResponse, Set<DcvError>> evaluatedSecondaryResponses) {
        // A secondary agent corroborates when that response had no validation errors.
        Map<String, Boolean> agentIdToCorroboration = evaluatedSecondaryResponses.entrySet()
                                                              .stream()
                                                              .collect(HashMap::new, (map, value) -> map.put(value.getKey().agentId(), value.getValue().isEmpty()), HashMap::putAll);
        return MpicDetails.builder()
                       .corroborated(corroborated)
                       .agentIdToCorroboration(agentIdToCorroboration)
                       .secondaryServersCorroborated(agentIdToCorroboration.values().stream().filter(Boolean::booleanValue).count())
                       .primaryAgentId(mpicDnsDetails.mpicDetails().primaryAgentId())
                       .secondaryServersChecked(mpicDnsDetails.secondaryDnsResponses().size())
                       .dnssecDetails(mpicDnsDetails.mpicDetails().dnssecDetails())
                       .cnameChain(mpicDnsDetails.mpicDetails().cnameChain())
                       .build();
    }

    /**
     * Builds the response payload for a parsed persistent TXT record.
     *
     * @param parsedIssueValue parsed issue-value data
     * @return normalized persistent TXT response payload
     */
    private static PersistentTxtResponse buildTxtResponse(ParsedIssueValue parsedIssueValue) {
        String accountUri = Optional.ofNullable(parsedIssueValue.parameters().get(ACCOUNT_URI_KEY))
                                    .map(List::getFirst)
                                    .orElse(null);
        Long persistUntil = Optional.ofNullable(parsedIssueValue.parameters().get(PERSIST_UNTIL_KEY))
                                    .map(List::getFirst)
                                    .map(PersistentValueHandler::tryParseLong)
                                    .orElse(null);
        return PersistentTxtResponse.builder()
                       .accountUri(accountUri)
                       .persistUntil(persistUntil)
                       .parsedTxtRecord(parsedIssueValue.parameters()).build();
    }

    private static Long tryParseLong(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }


    /**
     * Find the first txt record that is considered valid.
     * If no valid records are found, return the best invalid record for error reporting using this
     * ordered priority:
     * <ol>
     *   <li>A record with only a persistUntil-related error ({@code INVALID_PERSIST_UNTIL},
     *   {@code MULTIPLE_PERSIST_UNTIL}, or {@code PERSISTENT_RECORD_EXPIRED}).</li>
     *   <li>A record with issuer-domain errors where account URI is otherwise valid.</li>
     *   <li>The first remaining invalid record, excluding records that only contain
     *   {@code ACCOUNT_URI_MISMATCH}.</li>
     * </ol>
     * If no candidate matches these priorities, this method returns empty.
     *
     * @param dnsRecords TXT records returned by DNS lookup
     * @param accountUri account URI expected in the record
     * @return the first valid parsed record, or the best invalid record candidate for error reporting
     */
    private Optional<ParsedIssueValue> findAndParseMostValidPersistentRecord(List<DnsRecord> dnsRecords, String accountUri) {
        List<ParsedIssueValue> parsedRecords = dnsRecords.stream()
                                                       //records come back from mpic with a '.' after the domain
                                                       .map(DnsRecord::value)
                                                       .map(IssueValueParser::parse)
                                                       .toList();
        parsedRecords.forEach(parsedRecord -> {
            parsedRecord.addDcvErrors(evaluateParsedRecordAndUpdateDcvErrors(Optional.of(parsedRecord), accountUri));
        });

        Optional<ParsedIssueValue> matchingValidRecord = parsedRecords.stream()
                                                                 .filter(parsedRecord -> parsedRecord.dcvErrors().isEmpty())
                                                                 .findFirst();
        if (matchingValidRecord.isPresent()) {
            return matchingValidRecord;
        }

        // Prefer exposing a record with only a persistUntil error when available.
        Optional<ParsedIssueValue> invalidPersistUntil = parsedRecords.stream()
                                                                 .filter(parsedRecord -> parsedRecord.dcvErrors().size() == 1)
                                                                 .filter(PersistentValueHandler::hasPersistUntilError)
                                                                 .findFirst();

        if (invalidPersistUntil.isPresent()) {
            return invalidPersistUntil;
        }

        // Otherwise prefer a record that only fails issuer checks while account URI is valid.
        Optional<ParsedIssueValue> validAccountInvalidIssuer = parsedRecords.stream()
                                                                        .filter(x -> hasInvalidIssuer(x) && !hasInvalidAccountUri(x))
                                                                        .findFirst();
        if (validAccountInvalidIssuer.isPresent()) {
            return validAccountInvalidIssuer;
        }

        Optional<ParsedIssueValue> accountUriMismatchOnly = parsedRecords.stream()
                                                                    .filter(parsedRecord -> parsedRecord.dcvErrors().size() == 1
                                                                                                    && parsedRecord.dcvErrors().contains(DcvError.ACCOUNT_URI_MISMATCH))
                                                                    .findFirst();
        if (accountUriMismatchOnly.isPresent()) {
            return accountUriMismatchOnly;
        }

        // If no prioritized match exists, return the first parsed invalid record so that
        // its specific validation errors are surfaced instead of DNS_LOOKUP_RECORD_NOT_FOUND.
        return parsedRecords.stream()
                       .findFirst();
    }

    private static boolean hasPersistUntilError(ParsedIssueValue parsedIssueValue) {
        return parsedIssueValue.dcvErrors().contains(DcvError.INVALID_PERSIST_UNTIL)
                       || parsedIssueValue.dcvErrors().contains(DcvError.MULTIPLE_PERSIST_UNTIL)
                       || parsedIssueValue.dcvErrors().contains(DcvError.PERSISTENT_RECORD_EXPIRED);
    }

    private static boolean hasInvalidAccountUri(ParsedIssueValue parsedIssueValue) {
        return parsedIssueValue.dcvErrors().contains(DcvError.ACCOUNT_URI_REQUIRED) ||
                       parsedIssueValue.dcvErrors().contains(DcvError.MULTIPLE_ACCOUNT_URI) ||
                       parsedIssueValue.dcvErrors().contains(DcvError.ACCOUNT_URI_MISMATCH);
    }

    private static boolean hasInvalidIssuer(ParsedIssueValue x) {
        return x.dcvErrors().contains(DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED) || x.dcvErrors().contains(DcvError.ISSUER_DOMAIN_NAME_REQUIRED);
    }


    private Set<DcvError> evaluateParsedRecordAndUpdateDcvErrors(Optional<ParsedIssueValue> parsedPrimaryRecord, String accountUri) {
        if (parsedPrimaryRecord.isEmpty()) {
            return Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND);
        }
        ParsedIssueValue issueValue = parsedPrimaryRecord.get();
        Set<DcvError> errors = new HashSet<>();
        errors.addAll(getIssuerDomainErrors(issueValue));
        errors.addAll(getAccountUriErrors(accountUri, issueValue));
        errors.addAll(getPersistUntilErrors(issueValue));
        issueValue.addDcvErrors(errors);
        return errors;
    }

    private static Set<DcvError> getPersistUntilErrors(ParsedIssueValue issueValue) {
        Set<DcvError> errors = new HashSet<>();
        var validuntilList = issueValue.parameters().get(PERSIST_UNTIL_KEY);
        if (validuntilList != null && !validuntilList.isEmpty()) {
            if (validuntilList.size() > 1) {
                errors.add(DcvError.MULTIPLE_PERSIST_UNTIL);
            }
            var persistValue = validuntilList.getFirst();
            try {
                long unixTimestamp = Long.parseLong(persistValue);
                if (unixTimestamp < 0) {
                    errors.add(DcvError.INVALID_PERSIST_UNTIL);
                } else {
                    Instant persistUntil = Instant.ofEpochSecond(unixTimestamp);
                    if (Instant.now().isAfter(persistUntil)) {
                        errors.add(DcvError.PERSISTENT_RECORD_EXPIRED);
                    }
                }
            } catch (NumberFormatException | DateTimeException e) {
                errors.add(DcvError.INVALID_PERSIST_UNTIL);
            }
        }
        return errors;
    }

    private static Set<DcvError> getAccountUriErrors(String accountUri, ParsedIssueValue issueValue) {
        Set<DcvError> errors = new HashSet<>();
        var accountUriList = issueValue.parameters().get(ACCOUNT_URI_KEY);
        if (accountUriList == null || accountUriList.isEmpty()) {
            errors.add(DcvError.ACCOUNT_URI_REQUIRED);
        } else if (accountUriList.size() > 1) {
            errors.add(DcvError.MULTIPLE_ACCOUNT_URI);
        } else if (!accountUri.equals(accountUriList.getFirst())) {
            errors.add(DcvError.ACCOUNT_URI_MISMATCH);
        }
        return errors;
    }

    private Set<DcvError> getIssuerDomainErrors(ParsedIssueValue issueValue) {
        Set<DcvError> errors = new HashSet<>();
        String issuerDomainName = issueValue.issuerDomainName();

        if (issuerDomainName == null || issuerDomainName.isEmpty()) {
            errors.add(DcvError.ISSUER_DOMAIN_NAME_REQUIRED);
        } else if (!this.allowedIssuerDomains.contains(issuerDomainName.toLowerCase(Locale.ROOT))) {
            errors.add(DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED);
        }
        return errors;
    }

}
