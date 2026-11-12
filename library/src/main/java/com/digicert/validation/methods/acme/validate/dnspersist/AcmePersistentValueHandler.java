package com.digicert.validation.methods.acme.validate.dnspersist;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.AcmeDnsPersistValidationException;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.dns.validate.handlers.PersistentValueHandler;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import com.digicert.validation.utils.AcmeAccountUriHasher;
import com.digicert.validation.utils.MpicCorroborationEvaluator;
import com.digicert.validation.utils.StateValidationUtils;
import com.digicert.validation.utils.issueValue.IssueValueParser;
import com.digicert.validation.utils.issueValue.ParsedIssueValue;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Handles validation of the ACME {@code acme-dns-persist-01} persistent-value DNS challenge
 * (BR 3.2.2.4.22 overlaid with IETF draft {@code draft-ietf-acme-dns-persist-02}).
 *
 * <p>Like {@link PersistentValueHandler}, the caller never supplies a pre-hashed {@code accounturi} value
 * (neither handler receives one). Instead, this handler is given the raw ACME account URL and a list of
 * account-key thumbprints, and computes candidate hashed {@code accounturi} values on demand (per
 * {@link AcmeAccountUriHasher}) against each DNS record's {@code accounturi} parameter, trying each
 * supplied thumbprint &mdash; in the caller-supplied order, which should list the most-likely-to-succeed
 * thumbprint first &mdash; against every configured {@code accountHashPrefix} and both domain forms (exact
 * validated domain name and the domain-independent {@code *} opt-out), stopping at the first match. Hashes
 * are never precomputed for every thumbprint up front: with potentially many historical thumbprints in
 * play, this keeps the common case (an early thumbprint matches) cheap regardless of how long the supplied
 * thumbprint list is.
 *
 * <p>Because multiple thumbprints and multiple account-hash prefixes (and therefore multiple valid
 * candidate hashes) may be in play, there is no single expected value known up front to pass as MPIC's
 * {@code valueToCheck}. This handler therefore performs validation in two steps:
 * <ol>
 *     <li><b>Primary-only discovery</b> via {@link MpicDnsService#getPrimaryDnsDetails}: a genuine
 *     primary-only lookup with no corroboration judgment at all. The primary's records are matched
 *     against the full candidate list to determine which single candidate hash it observed.</li>
 *     <li><b>Full corroborated lookup</b> via {@link MpicDnsService#getDnsDetails} with that one matched
 *     hash passed as {@code valueToCheck}: now that a single concrete value is known, MPIC can run its own
 *     native, correct "does this value appear" check (instead of falling back to the "are the primary's
 *     and each secondary's entire raw TXT record sets byte-identical" check it uses when
 *     {@code valueToCheck} is empty &mdash; the same fallback used for value-less methods like CAA). This
 *     also avoids MPIC's secondary-polling loop short-circuiting on the wrong criterion, which could
 *     otherwise leave this handler with incomplete secondary data to work from.</li>
 * </ol>
 * MPIC's own corroboration result handles "did each secondary observe this value" (per the Baseline
 * Requirements' Multi-Perspective Issuance Corroboration rule that a secondary must observe the same
 * {@code accounturi} as the primary); this handler additionally re-applies its own semantic checks
 * (issuer-domain allowance, {@code persistUntil} validity, duplicate/missing {@code accounturi}) to each
 * agent's own record content, since MPIC's value-presence check knows nothing about those business rules.
 */
public final class AcmePersistentValueHandler {

    /** Prefix used for persistent TXT DNS lookups (shared with the non-ACME persistent-value method). */
    public static final String PERSISTENT_DNS_LABEL = "_validation-persist.";
    /** Issue-value parameter key for account URI. */
    public static final String ACCOUNT_URI_KEY = "accounturi";
    /** Issue-value parameter key for expiration timestamp in epoch seconds. */
    public static final String PERSIST_UNTIL_KEY = "persistUntil";
    /** Issue-value parameter key for reuse-scope policy. */
    public static final String POLICY_KEY = "policy";
    /** The only recognized value for the {@code policy} parameter that this handler surfaces. */
    public static final String POLICY_WILDCARD_VALUE = "wildcard";

    /** The canonical RFC 7638 SHA-256 JWK Thumbprint shape: 43 unpadded base64url characters. */
    private static final Pattern CANONICAL_THUMBPRINT_PATTERN = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final MpicDnsService mpicDnsService;
    private final Set<String> allowedIssuerDomains;
    private final Set<String> accountHashPrefixes;

    public AcmePersistentValueHandler(DcvContext dcvContext) {
        this.mpicDnsService = dcvContext.get(MpicDnsService.class);
        this.allowedIssuerDomains = dcvContext.getDcvConfiguration().getAllowedIssuerDomains();
        this.accountHashPrefixes = dcvContext.getDcvConfiguration().getAccountHashPrefixes();
    }

    /**
     * Validates an ACME persistent-value DNS challenge.
     *
     * @param request validation request
     * @return a successful {@link AcmeDnsPersistValidationResponse}
     * @throws ValidationException when validation fails
     * @throws InputException when request state or required inputs are invalid
     * @throws IllegalStateException when no issuer domains or account hash prefixes have been configured.
     */
    public AcmeDnsPersistValidationResponse validate(AcmeDnsPersistValidationRequest request) throws DcvException {
        if (this.allowedIssuerDomains.isEmpty()) {
            throw new IllegalStateException("Allowed issuer domains list is empty");
        }
        if (this.accountHashPrefixes.isEmpty()) {
            throw new IllegalStateException("Account hash prefixes list is empty");
        }
        verifyRequest(request);

        String domainWithPersistLabel = PERSISTENT_DNS_LABEL + request.getDomain();

        // Step 1: genuine primary-only discovery. No corroboration judgment is made here at all; this
        // just tells us what the primary agent saw, so we can figure out which single candidate matches.
        PrimaryDnsResponse primaryResponse = this.mpicDnsService.getPrimaryDnsDetails(domainWithPersistLabel, DnsType.TXT);
        DcvError primaryHardFailure = this.mpicDnsService.mapToDcvErrorOrNull(primaryResponse, MpicStatus.CORROBORATED);
        if (primaryHardFailure != null) {
            throw new AcmeDnsPersistValidationException(Set.of(primaryHardFailure), request);
        }

        MatchResult primaryMatch = findAndParseMostValidPersistentRecord(primaryResponse.dnsRecords(), request);
        if (!primaryMatch.parsedIssueValue().dcvErrors().isEmpty()) {
            throw new AcmeDnsPersistValidationException(primaryMatch.parsedIssueValue().dcvErrors(), request);
        }
        String matchedHash = primaryMatch.matchedCandidate().hashedUri();

        // Step 2: full corroborated lookup, now with the one matched hash as valueToCheck, so MPIC's own
        // per-secondary corroboration is meaningful. MPIC reports a failed quorum as the synthetic
        // MPIC_CORROBORATION_ERROR; that one is deliberately not treated as a hard failure here so the
        // per-secondary evaluation below can report the specific reason (mismatch, issuer, persistUntil).
        // Every other error (lookup/agent failure, invalid response, DNSSEC failure, no records) still
        // fails fast.
        MpicDnsDetails mpicDnsDetails = this.mpicDnsService.getDnsDetails(domainWithPersistLabel, DnsType.TXT, matchedHash);
        if (mpicDnsDetails.dcvError() != null && mpicDnsDetails.dcvError() != DcvError.MPIC_CORROBORATION_ERROR) {
            throw new AcmeDnsPersistValidationException(Set.of(mpicDnsDetails.dcvError()), request);
        }
        if (mpicDnsDetails.dnsRecords() == null || mpicDnsDetails.dnsRecords().isEmpty()) {
            throw new AcmeDnsPersistValidationException(Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND), request);
        }

        // Re-validate against the "final" primary record from this second call (not the discovery
        // response from step 1), so that any change between the two calls (e.g. the record being
        // modified/removed) is caught rather than silently trusting stale discovery data.
        MatchResult finalPrimaryMatch = findAndParseMostValidPersistentRecord(mpicDnsDetails.dnsRecords(), request);
        if (!finalPrimaryMatch.parsedIssueValue().dcvErrors().isEmpty()) {
            throw new AcmeDnsPersistValidationException(finalPrimaryMatch.parsedIssueValue().dcvErrors(), request);
        }
        if (finalPrimaryMatch.matchedCandidate() == null || !finalPrimaryMatch.matchedCandidate().hashedUri().equals(matchedHash)) {
            // The record changed between the discovery call and the corroborated call: what MPIC
            // corroborated is no longer what the final primary shows. Treat as a mismatch rather than
            // silently using either the stale or the new value.
            throw new AcmeDnsPersistValidationException(Set.of(DcvError.ACCOUNT_URI_MISMATCH), request);
        }

        // MPIC's own per-secondary `corroborates` flag already tells us whether that secondary observed
        // the matched value (a correct, native check now that valueToCheck is populated). We additionally
        // re-apply our own semantic checks (issuer, persistUntil, duplicate accounturi) to each
        // corroborating secondary's own record content, since MPIC's value-presence check does not know
        // about those business rules.
        HashMap<SecondaryDnsResponse, Set<DcvError>> evaluatedSecondaryResponses = mpicDnsDetails.secondaryDnsResponses().stream().collect(HashMap::new, (map, res) -> {
            Set<DcvError> errors = evaluateSecondarySemantics(res, matchedHash);
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

        if (!corroborates) {
            throw new AcmeDnsPersistValidationException(aggregatedErrors, request);
        }

        return new AcmeDnsPersistValidationResponse(
                getMpicDetails(mpicDnsDetails, true, evaluatedSecondaryResponses),
                domainWithPersistLabel,
                buildTxtResponse(finalPrimaryMatch));
    }

    private void verifyRequest(AcmeDnsPersistValidationRequest request) throws DcvException {
        StateValidationUtils.verifyValidationState(request.getValidationState(), DcvMethod.BR_3_2_2_4_22);

        if (request.getAccountUri() == null || request.getAccountUri().isBlank()) {
            throw new InputException(DcvError.ACCOUNT_URI_REQUIRED);
        }
        verifyAccountUri(request.getAccountUri());

        if (request.getAccountThumbprints() == null || request.getAccountThumbprints().isEmpty()
                || request.getAccountThumbprints().stream().anyMatch(thumbprint -> thumbprint == null || thumbprint.isBlank())) {
            throw new InputException(DcvError.ACME_THUMBPRINT_REQUIRED);
        }
        for (String thumbprint : request.getAccountThumbprints()) {
            if (!isCanonicalThumbprint(thumbprint)) {
                throw new InputException(DcvError.INVALID_ACCOUNT_THUMBPRINT);
            }
        }
    }

    /**
     * Validates that the supplied account URI is an absolute, US-ASCII URI, per the draft's requirement
     * that the account URL is encoded as US-ASCII octets (RFC 3986 is US-ASCII; RFC 8555 Section 7.3).
     * A syntactically valid but relative or non-ASCII value is rejected rather than silently accepted and
     * then mangled by ASCII-only hashing downstream (which would otherwise make visibly different URLs
     * hash identically).
     *
     * @param value the account URI to validate
     * @throws InputException if the value is not a syntactically valid, absolute, US-ASCII URI
     */
    private void verifyAccountUri(String value) throws InputException {
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw new InputException(DcvError.INVALID_ACCOUNT_URI, e);
        }
        if (!uri.isAbsolute()) {
            throw new InputException(DcvError.INVALID_ACCOUNT_URI);
        }
        if (!isUsAscii(value)) {
            throw new InputException(DcvError.INVALID_ACCOUNT_URI);
        }
    }

    private static boolean isUsAscii(String value) {
        return value.chars().allMatch(c -> c < 128);
    }

    private static boolean isCanonicalThumbprint(String thumbprint) {
        return CANONICAL_THUMBPRINT_PATTERN.matcher(thumbprint).matches();
    }

    /**
     * Checks a secondary agent against its own MPIC-computed corroboration verdict and our semantic rules.
     * <p>
     * {@link SecondaryDnsResponse#corroborates()} is MPIC's own determination (since {@code valueToCheck}
     * is the primary's matched {@code accounturi}) of whether this secondary observed that exact value,
     * satisfying the Baseline Requirements' rule that a secondary must observe the <em>same</em>
     * {@code accounturi} as the primary. If it did, we additionally require that at least one of this
     * secondary's records carrying that {@code accounturi} passes the issuer, {@code persistUntil} and
     * duplicate-{@code accounturi} checks. No hashing is repeated: the matched value is already known.
     */
    private Set<DcvError> evaluateSecondarySemantics(SecondaryDnsResponse secondaryDnsResponse, String matchedAccountUri) {
        if (!secondaryDnsResponse.corroborates()) {
            return Set.of(DcvError.ACCOUNT_URI_MISMATCH);
        }
        Set<DcvError> bestErrors = null;
        for (DnsRecord dnsRecord : secondaryDnsResponse.dnsRecords()) {
            ParsedIssueValue parsedRecord = IssueValueParser.parse(dnsRecord.value());
            List<String> accountUris = parsedRecord.parameters().get(ACCOUNT_URI_KEY);
            if (accountUris == null || !accountUris.contains(matchedAccountUri)) {
                continue;
            }
            parsedRecord.addDcvErrors(getRecordErrors(parsedRecord));
            Set<DcvError> errors = parsedRecord.dcvErrors();
            if (errors.isEmpty()) {
                return errors;
            }
            if (bestErrors == null || errors.size() < bestErrors.size()) {
                bestErrors = errors;
            }
        }
        return bestErrors == null ? Set.of(DcvError.ACCOUNT_URI_MISMATCH) : bestErrors;
    }

    /**
     * A single candidate hashed URI, along with the thumbprint, account-hash prefix, and domain-form
     * that produced it.
     */
    private record CandidateHash(String thumbprint, String accountHashPrefix, boolean wildcardOptOut, String hashedUri) {
    }

    /**
     * The result of matching a parsed issue-value against the candidate hashes: the matched candidate
     * (if any) and the parsed issue-value with any accumulated DCV errors.
     */
    private record MatchResult(CandidateHash matchedCandidate, ParsedIssueValue parsedIssueValue) {
    }

    /**
     * Normalizes a domain name to the canonical lowercase A-label, no-trailing-dot form required by the
     * draft's hash construction ({@code domain_name}), without mutating the caller's original request value
     * used elsewhere (DNS lookup label, response {@code domain} field).
     */
    private static String canonicalizeDomainForHashing(String domain) {
        String normalized = domain.strip().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static AcmePersistentTxtResponse buildTxtResponse(MatchResult matchResult) {
        ParsedIssueValue parsedIssueValue = matchResult.parsedIssueValue();
        Long persistUntil = Optional.ofNullable(parsedIssueValue.parameters().get(PERSIST_UNTIL_KEY))
                                    .map(List::getFirst)
                                    .map(AcmePersistentValueHandler::tryParseLong)
                                    .orElse(null);
        boolean policyWildcard = Optional.ofNullable(parsedIssueValue.parameters().get(POLICY_KEY))
                                          .map(List::getFirst)
                                          .map(value -> POLICY_WILDCARD_VALUE.equalsIgnoreCase(value))
                                          .orElse(false);
        CandidateHash matched = matchResult.matchedCandidate();
        return AcmePersistentTxtResponse.builder()
                       .matchedThumbprint(matched == null ? null : matched.thumbprint())
                       .matchedWildcardOptOut(matched != null && matched.wildcardOptOut())
                       .matchedIssuerDomain(parsedIssueValue.issuerDomainName())
                       .policyWildcard(policyWildcard)
                       .persistUntil(persistUntil)
                       .parsedTxtRecord(parsedIssueValue.parameters())
                       .build();
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
     * Find the first txt record whose accounturi matches one of the candidate hashes, considering issuer and
     * persistUntil validity. If no valid record is found, returns the best invalid record candidate for
     * error reporting, mirroring {@link PersistentValueHandler}'s prioritization approach.
     * <p>
     * Candidate hashes are computed lazily, thumbprint-by-thumbprint in the caller-supplied order (which
     * should list the most-likely-to-succeed thumbprint first), and each hash is computed only once and
     * checked against every record before moving to the next thumbprint.
     */
    private MatchResult findAndParseMostValidPersistentRecord(List<DnsRecord> dnsRecords, AcmeDnsPersistValidationRequest request) {
        List<ParsedIssueValue> parsedRecords = dnsRecords.stream()
                                                       .map(DnsRecord::value)
                                                       .map(IssueValueParser::parse)
                                                       .toList();

        if (parsedRecords.isEmpty()) {
            return new MatchResult(null, new ParsedIssueValue(null, new LinkedHashMap<>(),
                    new IssueValueParser.IssueValueParsingException(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND, "no records found")));
        }

        // Errors that do not depend on which thumbprint matches (issuer, persistUntil, missing/multiple accounturi).
        for (ParsedIssueValue parsedRecord : parsedRecords) {
            parsedRecord.addDcvErrors(getRecordErrors(parsedRecord));
        }

        Map<ParsedIssueValue, CandidateHash> matches = new IdentityHashMap<>();
        MatchResult validResult = findMatchingCandidates(parsedRecords, request, matches);
        if (validResult != null) {
            return validResult;
        }

        List<MatchResult> matchResults = new ArrayList<>();
        for (ParsedIssueValue parsedRecord : parsedRecords) {
            CandidateHash matched = matches.get(parsedRecord);
            if (matched == null && isMatchable(parsedRecord)) {
                parsedRecord.addDcvErrors(Set.of(DcvError.ACCOUNT_URI_MISMATCH));
            }
            matchResults.add(new MatchResult(matched, parsedRecord));
        }

        // Prefer exposing a record with only a persistUntil or duplicate-policy error when available.
        Optional<MatchResult> invalidPersistUntil = matchResults.stream()
                                                             .filter(result -> result.parsedIssueValue().dcvErrors().size() == 1)
                                                             .filter(result -> hasPersistUntilError(result.parsedIssueValue())
                                                                                       || result.parsedIssueValue().dcvErrors().contains(DcvError.MULTIPLE_POLICY))
                                                             .findFirst();
        if (invalidPersistUntil.isPresent()) {
            return invalidPersistUntil.get();
        }

        Optional<MatchResult> validAccountInvalidIssuer = matchResults.stream()
                                                                   .filter(result -> hasInvalidIssuer(result.parsedIssueValue()) && !hasInvalidAccountUri(result.parsedIssueValue()))
                                                                   .findFirst();
        if (validAccountInvalidIssuer.isPresent()) {
            return validAccountInvalidIssuer.get();
        }

        // A record whose accounturi uses an unsupported hash algorithm is reported as malformed.
        Optional<MatchResult> unsupportedHashAlgorithm = matchResults.stream()
                                                                  .filter(result -> hasUnsupportedHashAlgorithm(result.parsedIssueValue()))
                                                                  .findFirst();
        if (unsupportedHashAlgorithm.isPresent()) {
            return unsupportedHashAlgorithm.get();
        }

        Optional<MatchResult> accountUriMismatchOnly = matchResults.stream()
                                                                .filter(result -> result.parsedIssueValue().dcvErrors().size() == 1
                                                                                           && result.parsedIssueValue().dcvErrors().contains(DcvError.ACCOUNT_URI_MISMATCH))
                                                                .findFirst();
        if (accountUriMismatchOnly.isPresent()) {
            return accountUriMismatchOnly.get();
        }

        return matchResults.getFirst();
    }

    /**
     * Matches each record's {@code accounturi} values against the candidate hashes, filling {@code matches}
     * with the first candidate found for each record. Records without an {@code accounturi}, or whose
     * {@code accounturi} uses an unsupported hash algorithm, are skipped.
     * <p>
     * For each thumbprint (in the caller-supplied order) the exact-domain and {@code *} opt-out hashes are
     * computed once. A record's value is a match when it ends with that hash and equals
     * {@code <configured accountHashPrefix>sha-256/<hash>} for one of the configured prefixes, so no hash is
     * recomputed per prefix. Returns the first record that matches and has no other errors, or
     * {@code null} when there is none.
     */
    private MatchResult findMatchingCandidates(List<ParsedIssueValue> records, AcmeDnsPersistValidationRequest request,
                                               Map<ParsedIssueValue, CandidateHash> matches) {
        List<ParsedIssueValue> recordsWithAccountUri = records.stream().filter(this::isMatchable).toList();
        String canonicalDomain = canonicalizeDomainForHashing(request.getDomain());

        for (String thumbprint : request.getAccountThumbprints()) {
            String exactHash = AcmeAccountUriHasher.computeHash(canonicalDomain, thumbprint, request.getAccountUri());
            String wildcardHash = AcmeAccountUriHasher.computeWildcardOptOutHash(thumbprint, request.getAccountUri());
            for (ParsedIssueValue record : recordsWithAccountUri) {
                if (matches.containsKey(record)) {
                    continue;
                }
                for (String accountUri : record.parameters().get(ACCOUNT_URI_KEY)) {
                    CandidateHash candidate = matchAccountUri(accountUri, thumbprint, exactHash, false);
                    if (candidate == null) {
                        candidate = matchAccountUri(accountUri, thumbprint, wildcardHash, true);
                    }
                    if (candidate != null) {
                        matches.put(record, candidate);
                        if (record.dcvErrors().isEmpty()) {
                            return new MatchResult(candidate, record);
                        }
                        break;
                    }
                }
            }
        }
        return null;
    }

    private CandidateHash matchAccountUri(String accountUri, String thumbprint, String hash, boolean wildcardOptOut) {
        if (!accountUri.endsWith(hash)) {
            return null;
        }
        for (String prefix : accountHashPrefixes) {
            if (accountUri.equals(prefix + AcmeAccountUriHasher.HASH_ALGORITHM_IDENTIFIER + "/" + hash)) {
                return new CandidateHash(thumbprint, prefix, wildcardOptOut, accountUri);
            }
        }
        return null;
    }

    private static boolean hasAccountUri(ParsedIssueValue issueValue) {
        List<String> accountUris = issueValue.parameters().get(ACCOUNT_URI_KEY);
        return accountUris != null && !accountUris.isEmpty();
    }

    /** Errors that do not depend on which candidate hash matches: issuer, persistUntil, accounturi and policy problems. */
    private Set<DcvError> getRecordErrors(ParsedIssueValue issueValue) {
        Set<DcvError> errors = new HashSet<>();
        errors.addAll(getIssuerDomainErrors(issueValue));
        errors.addAll(getPersistUntilErrors(issueValue));
        List<String> accountUriList = issueValue.parameters().get(ACCOUNT_URI_KEY);
        if (accountUriList == null || accountUriList.isEmpty()) {
            errors.add(DcvError.ACCOUNT_URI_REQUIRED);
        } else if (accountUriList.size() > 1) {
            errors.add(DcvError.MULTIPLE_ACCOUNT_URI);
        }
        if (hasUnsupportedHashAlgorithm(issueValue)) {
            errors.add(DcvError.INVALID_ISSUE_VALUE_FORMAT);
        }
        List<String> policyList = issueValue.parameters().get(POLICY_KEY);
        if (policyList != null && policyList.size() > 1) {
            errors.add(DcvError.MULTIPLE_POLICY);
        }
        return errors;
    }

    /** A record can be matched against candidate hashes when it has an accounturi with a supported hash algorithm. */
    private boolean isMatchable(ParsedIssueValue issueValue) {
        return hasAccountUri(issueValue) && !hasUnsupportedHashAlgorithm(issueValue);
    }

    private boolean hasUnsupportedHashAlgorithm(ParsedIssueValue issueValue) {
        List<String> accountUris = issueValue.parameters().get(ACCOUNT_URI_KEY);
        return accountUris != null && accountUris.stream().anyMatch(this::usesUnsupportedHashAlgorithm);
    }

    /**
     * An accounturi has the form {@code <accountHashPrefix><hash-alg>/<hash>}. It uses an unsupported algorithm
     * when, for a configured prefix, the segment after the prefix is some {@code <alg>/} other than
     * {@code sha-256/} and no configured prefix gives {@code sha-256/}.
     */
    private boolean usesUnsupportedHashAlgorithm(String accountUri) {
        boolean otherAlgorithm = false;
        for (String prefix : accountHashPrefixes) {
            if (!accountUri.startsWith(prefix)) {
                continue;
            }
            String rest = accountUri.substring(prefix.length());
            if (rest.startsWith(AcmeAccountUriHasher.HASH_ALGORITHM_IDENTIFIER + "/")) {
                return false;
            }
            if (rest.indexOf('/') > 0) {
                otherAlgorithm = true;
            }
        }
        return otherAlgorithm;
    }

    private static Set<DcvError> getPersistUntilErrors(ParsedIssueValue issueValue) {
        Set<DcvError> errors = new HashSet<>();
        List<String> validUntilList = issueValue.parameters().get(PERSIST_UNTIL_KEY);
        if (validUntilList != null && !validUntilList.isEmpty()) {
            if (validUntilList.size() > 1) {
                errors.add(DcvError.MULTIPLE_PERSIST_UNTIL);
            }
            String persistValue = validUntilList.getFirst();
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

    private static boolean hasInvalidIssuer(ParsedIssueValue issueValue) {
        return issueValue.dcvErrors().contains(DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED) || issueValue.dcvErrors().contains(DcvError.ISSUER_DOMAIN_NAME_REQUIRED);
    }

    private static MpicDetails getMpicDetails(MpicDnsDetails mpicDnsDetails, boolean corroborated, HashMap<SecondaryDnsResponse, Set<DcvError>> evaluatedSecondaryResponses) {
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
}
