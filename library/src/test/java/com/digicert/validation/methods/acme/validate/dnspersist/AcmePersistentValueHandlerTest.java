package com.digicert.validation.methods.acme.validate.dnspersist;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.AcmeDnsPersistValidationException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import com.digicert.validation.utils.AcmeAccountUriHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link AcmePersistentValueHandler}.
 *
 * <p>The handler validates in two steps: (1) a genuine primary-only lookup via
 * {@link MpicDnsService#getPrimaryDnsDetails} to determine which single candidate hash the primary
 * observes, then (2) a full corroborated lookup via {@link MpicDnsService#getDnsDetails} with that one
 * matched hash populated as {@code valueToCheck}, so MPIC's own native value-presence corroboration (per
 * secondary, exposed as {@link SecondaryDnsResponse#corroborates()}) can run correctly. This handler
 * additionally re-applies its own semantic checks (issuer, persistUntil, duplicate accounturi) on top of
 * MPIC's presence-based verdict. Unlike {@code DnsValidator}'s handlers, this handler throws
 * {@link ValidationException} on failure rather than returning a response with an {@code isValid} flag.
 */
@ExtendWith(MockitoExtension.class)
class AcmePersistentValueHandlerTest {

    @Mock
    private MpicDnsService mpicDnsService;

    private AcmePersistentValueHandler handler;

    private static final String DOMAIN = "example.com";
    private static final String RECORD_NAME = "_validation-persist.example.com";
    private static final String ACCOUNT_HASH_PREFIX = "https://ca.example/account-hash/";
    private static final String ACCOUNT_URI = "https://ca.example/acct/123";
    // The example thumbprint from RFC 7638, Section 3.1, as referenced by draft-ietf-acme-dns-persist-02.
    private static final String ACTIVE_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    private static final String HISTORICAL_THUMBPRINT = "b64-encoded-historical-thumbprint-value-xxx";
    private static String hashedUri(String hash) {
        return ACCOUNT_HASH_PREFIX + AcmeAccountUriHasher.HASH_ALGORITHM_IDENTIFIER + "/" + hash;
    }

    private static final String EXACT_HASH = hashedUri(AcmeAccountUriHasher.computeHash(DOMAIN, ACTIVE_THUMBPRINT, ACCOUNT_URI));
    private static final String WILDCARD_HASH = hashedUri(AcmeAccountUriHasher.computeWildcardOptOutHash(ACTIVE_THUMBPRINT, ACCOUNT_URI));
    private static final String HISTORICAL_EXACT_HASH = hashedUri(AcmeAccountUriHasher.computeHash(DOMAIN, HISTORICAL_THUMBPRINT, ACCOUNT_URI));

    @BeforeEach
    void setUp() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .allowedIssuerDomains(List.of("authority.example"))
                .accountHashPrefixes(List.of(ACCOUNT_HASH_PREFIX))
                .build();

        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        handler = new AcmePersistentValueHandler(dcvContext);
    }

    @Test
    void validate_throwsIllegalStateExceptionWhenIssuerDomainsIsEmpty() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                                          .accountHashPrefixes(List.of(ACCOUNT_HASH_PREFIX))
                                          .build();
        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        AcmePersistentValueHandler handlerWithNoAllowedIssuers = new AcmePersistentValueHandler(dcvContext);
        assertThrows(IllegalStateException.class, () -> handlerWithNoAllowedIssuers.validate(null));
    }

    @Test
    void validate_throwsIllegalStateExceptionWhenAccountHashPrefixesListIsEmpty() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                                          .allowedIssuerDomains(List.of("authority.example"))
                                          .build();
        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        AcmePersistentValueHandler handlerWithNoPrefixes = new AcmePersistentValueHandler(dcvContext);
        assertThrows(IllegalStateException.class, () -> handlerWithNoPrefixes.validate(null));
    }

    // ---- verifyRequest tests ----

    static Stream<Arguments> invalidRequestScenarios() {
        return Stream.of(
                Arguments.of("invalid dcv method", acmeRequest(DcvMethod.BR_3_2_2_4_7, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT)), DcvError.INVALID_DCV_METHOD),
                Arguments.of("missing account uri", acmeRequest(DcvMethod.BR_3_2_2_4_22, null, List.of(ACTIVE_THUMBPRINT)), DcvError.ACCOUNT_URI_REQUIRED),
                Arguments.of("blank account uri", acmeRequest(DcvMethod.BR_3_2_2_4_22, " ", List.of(ACTIVE_THUMBPRINT)), DcvError.ACCOUNT_URI_REQUIRED),
                Arguments.of("missing thumbprints", acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, null), DcvError.ACME_THUMBPRINT_REQUIRED),
                Arguments.of("empty thumbprints", acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of()), DcvError.ACME_THUMBPRINT_REQUIRED)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidRequestScenarios")
    void validate_throwsForInvalidRequest(String description, AcmeDnsPersistValidationRequest request, DcvError expectedError) {
        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(expectedError));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForInvalidAccountUri() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, "http://[", List.of(ACTIVE_THUMBPRINT));

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_ACCOUNT_URI));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForRelativeAccountUri() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, "acct/123", List.of(ACTIVE_THUMBPRINT));

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_ACCOUNT_URI));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForNonAsciiAccountUri() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, "https://ca.example/acct/caf\u00e9", List.of(ACTIVE_THUMBPRINT));

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_ACCOUNT_URI));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForNullThumbprintEntryInList() {
        List<String> thumbprintsWithNull = new ArrayList<>();
        thumbprintsWithNull.add(ACTIVE_THUMBPRINT);
        thumbprintsWithNull.add(null);
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, thumbprintsWithNull);

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.ACME_THUMBPRINT_REQUIRED));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForMalformedThumbprintFormat() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of("not-a-valid-thumbprint"));

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_ACCOUNT_THUMBPRINT));
        verifyNoInteractions(mpicDnsService);
    }

    // ---- TXT lookup, parsing, and hash-matching tests (two-call design) ----

    @Test
    void validate_happyPath_exactDomainMatch() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertNotNull(response.acmePersistentTxtResponse());
        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
        assertFalse(response.acmePersistentTxtResponse().matchedWildcardOptOut());
        verify(mpicDnsService, times(1)).getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT);
        verify(mpicDnsService, times(1)).getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH);
    }

    @Test
    void validate_happyPath_wildcardOptOutMatch() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + WILDCARD_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, WILDCARD_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
        assertTrue(response.acmePersistentTxtResponse().matchedWildcardOptOut());
    }

    @Test
    void validate_historicalThumbprintOnlyMatches_stillValidates() throws Exception {
        // The record was published under a prior/historical account key, not the current active one.
        // The caller supplies both; the handler must accept a match against either.
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT, HISTORICAL_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + HISTORICAL_EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, HISTORICAL_EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(HISTORICAL_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    @Test
    void validate_multipleAccountHashPrefixesConfigured_matchesUsingOlderPrefix() throws Exception {
        // Simulates a prefix rotation: the CA now advertises a new prefix but still accepts records
        // computed under a previously-advertised one. Both are configured; the record was published
        // (and remains unrotated) under the older prefix.
        String newerPrefix = "https://ca.example/account-hash-v2/";
        DcvConfiguration multiPrefixConfig = new DcvConfiguration.DcvConfigurationBuilder()
                .allowedIssuerDomains(List.of("authority.example"))
                .accountHashPrefixes(List.of(ACCOUNT_HASH_PREFIX, newerPrefix))
                .build();
        DcvContext multiPrefixContext = spy(new DcvContext(multiPrefixConfig));
        doReturn(mpicDnsService).when(multiPrefixContext).get(MpicDnsService.class);
        AcmePersistentValueHandler multiPrefixHandler = new AcmePersistentValueHandler(multiPrefixContext);

        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        // EXACT_HASH was computed using the older ACCOUNT_HASH_PREFIX.
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = multiPrefixHandler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    @Test
    void validate_noConfiguredPrefixMatches_fails() throws Exception {
        String differentPrefix = "https://ca.example/account-hash-v2/";
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .allowedIssuerDomains(List.of("authority.example"))
                .accountHashPrefixes(List.of(differentPrefix))
                .build();
        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        AcmePersistentValueHandler handlerWithDifferentPrefix = new AcmePersistentValueHandler(dcvContext);

        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        // EXACT_HASH was computed using ACCOUNT_HASH_PREFIX, which is not configured for this handler.
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT))
                .thenReturn(primaryDnsResponse(dnsRecord(RECORD_NAME, issueValue)));

        ValidationException exception = assertThrows(ValidationException.class, () -> handlerWithDifferentPrefix.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
        verify(mpicDnsService, never()).getDnsDetails(any(), any(), any());
    }

    @Test
    void validate_policyWildcardPresent_surfacedInResponse() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH + "; policy=WILDCARD";
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertTrue(response.acmePersistentTxtResponse().policyWildcard());
    }

    @Test
    void validate_policyAbsent_notSurfacedAsWildcard() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertFalse(response.acmePersistentTxtResponse().policyWildcard());
    }

    @Test
    void validate_persistUntilPresent_surfacedInResponse() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        long future = Instant.now().plusSeconds(600).getEpochSecond();
        String issueValue = "authority.example; accounturi=" + EXACT_HASH + "; persistUntil=" + future;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(future, response.acmePersistentTxtResponse().persistUntil());
    }

    @Test
    void validate_unrecognizedTagIgnored() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH + "; futureparam=somevalue";
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertNotNull(response.acmePersistentTxtResponse());
    }

    @Test
    void validate_issuerDomainMismatch_fails() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "bad-authority.example; accounturi=" + EXACT_HASH;

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT))
                .thenReturn(primaryDnsResponse(dnsRecord(RECORD_NAME, issueValue)));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED));
        // Primary itself is invalid: no second (corroborated) call should ever be made.
        verify(mpicDnsService, never()).getDnsDetails(any(), any(), any());
    }

    @Test
    void validate_noCandidateMatches_fails() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=https://ca.example/account-hash/sha-256/does-not-match";

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT))
                .thenReturn(primaryDnsResponse(dnsRecord(RECORD_NAME, issueValue)));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
        verify(mpicDnsService, never()).getDnsDetails(any(), any(), any());
    }

    @Test
    void validate_multipleThumbprints_secondThumbprintMatches() throws Exception {
        String otherThumbprint = "b64-encoded-other-thumbprint-value-xxxxxxxx";
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(otherThumbprint, ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    @Test
    void validate_dnsRecordNotFound_fails() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT))
                .thenReturn(primaryDnsResponse(List.of()));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        verify(mpicDnsService, never()).getDnsDetails(any(), any(), any());
    }

    @Test
    void validate_genuinePrimaryAgentFailure_stillShortCircuits() {
        // A real agent-level failure reported via MpicDnsService.mapToDcvErrorOrNull must short-circuit
        // immediately, before any candidate matching or second (corroborated) call is attempted.
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));

        PrimaryDnsResponse failedPrimary = new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_TIMEOUT, null, List.of(), DnsType.TXT, RECORD_NAME, List.of());
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(failedPrimary);
        when(mpicDnsService.mapToDcvErrorOrNull(eq(failedPrimary), any())).thenReturn(DcvError.DNS_LOOKUP_TIMEOUT);

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_TIMEOUT));
        verify(mpicDnsService, never()).getDnsDetails(any(), any(), any());
    }

    @Test
    void validate_secondCallHardFailure_stillShortCircuits() throws Exception {
        // A genuine hard failure surfaced on the second (full/corroborated) call must still short-circuit,
        // (every error other than the synthetic MPIC_CORROBORATION_ERROR fails fast).
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(record));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetailsWithError(List.of(record), twoCorroboratingSecondaries(record), DcvError.DNS_LOOKUP_DNSSEC_FAILURE));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_DNSSEC_FAILURE));
    }

    @Test
    void validate_uppercaseDomain_stillMatchesCanonicalLowercaseHash() throws Exception {
        // The hash must be computed from the canonical lowercase A-label form of the domain (per the
        // draft's domain_name requirement), regardless of the case the caller supplied in the request.
        AcmeDnsPersistValidationRequest request = AcmeDnsPersistValidationRequest.builder()
                .domain("EXAMPLE.COM")
                .accountUri(ACCOUNT_URI)
                .accountThumbprints(List.of(ACTIVE_THUMBPRINT))
                .validationState(new ValidationState("EXAMPLE.COM", Instant.now(), DcvMethod.BR_3_2_2_4_22))
                .build();
        // EXACT_HASH was computed from the lowercase "example.com" domain.
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        String recordNameForUppercaseDomain = "_validation-persist.EXAMPLE.COM";
        DnsRecord record = dnsRecord(recordNameForUppercaseDomain, issueValue);

        when(mpicDnsService.getPrimaryDnsDetails(recordNameForUppercaseDomain, DnsType.TXT))
                .thenReturn(primaryDnsResponse(record));
        when(mpicDnsService.getDnsDetails(recordNameForUppercaseDomain, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(record), twoCorroboratingSecondaries(record)));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    @Test
    void validate_matchedIssuerDomainSurfacedInResponse() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals("authority.example", response.acmePersistentTxtResponse().matchedIssuerDomain());
    }

    @Test
    void validate_secondaryWithWrongIssuer_doesNotCorroborate_evenThoughHashMatches() throws Exception {
        // A secondary whose record has a matching accounturi hash (so MPIC's native value-presence check
        // says it corroborates) but a disallowed issuer must not count as corroborating merely because
        // the hash matched — this handler re-applies its own semantic checks on top of MPIC's verdict.
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        String wrongIssuerSameHash = "bad-authority.example; accounturi=" + EXACT_HASH;
        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, issueValue);

        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(
                        secondary("good-secondary", "ARIN", primaryRecord, true),
                        // MPIC says this secondary DID observe the matched hash (corroborates=true);
                        // our own semantic check must still reject it for the wrong issuer.
                        secondary("bad-secondary", "RIPE", dnsRecord(RECORD_NAME, wrongIssuerSameHash), true))));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertFalse(response.mpicDetails().agentIdToCorroboration().get("bad-secondary"));
        assertTrue(response.mpicDetails().agentIdToCorroboration().get("good-secondary"));
    }

    @Test
    void validate_secondaryWithExpiredPersistUntil_doesNotCorroborate_evenThoughHashMatches() throws Exception {
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        String expiredPersistUntil = "authority.example; accounturi=" + EXACT_HASH + "; persistUntil=1000000000";
        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, issueValue);

        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(
                        secondary("good-secondary", "ARIN", primaryRecord, true),
                        secondary("expired-secondary", "RIPE", dnsRecord(RECORD_NAME, expiredPersistUntil), true))));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertFalse(response.mpicDetails().agentIdToCorroboration().get("expired-secondary"));
        assertTrue(response.mpicDetails().agentIdToCorroboration().get("good-secondary"));
    }

    @Test
    void validate_secondaryObservesDifferentValue_mpicReportsNoCorroboration() throws Exception {
        // Per the BRs' MPIC rule, a secondary MUST observe the SAME accounturi as the primary to count as
        // corroborating. Since the second call's valueToCheck is the primary's matched hash
        // (HISTORICAL_EXACT_HASH here), MPIC itself (not our own code) determines that a secondary whose
        // record contains a *different* hash (EXACT_HASH) does not corroborate.
        String primaryIssueValue = "authority.example; accounturi=" + HISTORICAL_EXACT_HASH;
        String differentValidCandidateIssueValue = "authority.example; accounturi=" + EXACT_HASH;
        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, primaryIssueValue);

        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT, HISTORICAL_THUMBPRINT));
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, HISTORICAL_EXACT_HASH))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(
                        secondary("same-as-primary", "ARIN", primaryRecord, true),
                        // MPIC's own value-presence check correctly reports this as non-corroborating,
                        // since this secondary's record does not contain HISTORICAL_EXACT_HASH.
                        secondary("different-candidate", "RIPE", dnsRecord(RECORD_NAME, differentValidCandidateIssueValue), false))));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(HISTORICAL_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
        assertFalse(response.mpicDetails().agentIdToCorroboration().get("different-candidate"));
        assertTrue(response.mpicDetails().agentIdToCorroboration().get("same-as-primary"));
    }

    // ---- IETF draft worked-example regression tests (draft-ietf-acme-dns-persist-02, Section 4.3.4 / Section 10.4) ----

    /**
     * Reproduces draft Section 4.3.4 "Example: Authorizing Two CAs": two TXT records exist at the same
     * label, one per issuer. This handler, configured only for "authority.example", must ignore the
     * record for the other issuer and validate using only the matching one.
     */
    @Test
    void validate_multipleIssuerRecordsCoexist_onlyMatchingIssuerRecordIsUsed() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String ourIssuerRecord = "authority.example; accounturi=" + EXACT_HASH;
        String otherCaIssuerRecord = "other-ca.example; accounturi=https://other-ca.example/account-hash/sha-256/unrelated-value";

        DnsRecord ourRecord = dnsRecord(RECORD_NAME, ourIssuerRecord);
        DnsRecord otherCaRecord = dnsRecord(RECORD_NAME, otherCaIssuerRecord);

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT))
                .thenReturn(primaryDnsResponse(List.of(otherCaRecord, ourRecord)));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(otherCaRecord, ourRecord), List.of(
                        secondary("s1", "ARIN", ourRecord, true), secondary("s2", "RIPE", ourRecord, true))));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    /**
     * Reproduces draft Section 10.4 "Wildcard Validation Example": the record includes {@code policy=wildcard},
     * which authorizes the exact FQDN, specific subdomains, and wildcard certificates for the validated name
     * (scope enforcement is a caller/CIS concern; this handler only surfaces the flag).
     */
    @Test
    void validate_wildcardValidationExample_policyFlagSurfaced() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH + "; policy=wildcard";
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);

        stubPrimaryAndFull(record, EXACT_HASH, twoCorroboratingSecondaries(record));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertTrue(response.acmePersistentTxtResponse().policyWildcard());
        assertFalse(response.acmePersistentTxtResponse().matchedWildcardOptOut());
    }

    @Test
    void validate_corroborationFails_whenSecondariesDoNotMatch() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        String differentIssueValue = "authority.example; accounturi=https://ca.example/account-hash/sha-256/some-other-value";

        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, issueValue);
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(
                        secondary("s1", "ARIN", dnsRecord(RECORD_NAME, differentIssueValue), false),
                        secondary("s2", "RIPE", dnsRecord(RECORD_NAME, differentIssueValue), false),
                        secondary("s3", "APNIC", dnsRecord(RECORD_NAME, differentIssueValue), false)
                )));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        // Secondaries that MPIC reports as not corroborating surface ACCOUNT_URI_MISMATCH; the generic
        // MPIC_CORROBORATION_ERROR is only added when no other secondary error was found.
        assertTrue(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
    }

    @Test
    void validate_realNonCorroboratedStatus_surfacesSpecificSecondaryError() throws Exception {
        // In production MpicDnsService maps a NON_CORROBORATED status to MPIC_CORROBORATION_ERROR on the
        // result's dcvError. That synthetic error must not short-circuit before per-secondary evaluation,
        // so the specific reason (ACCOUNT_URI_MISMATCH) is reported instead of the generic error.
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH;
        String differentIssueValue = "authority.example; accounturi=https://ca.example/account-hash/sha-256/some-other-value";
        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, issueValue);

        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetailsWithError(List.of(primaryRecord), List.of(
                        secondary("s1", "ARIN", dnsRecord(RECORD_NAME, differentIssueValue), false),
                        secondary("s2", "RIPE", dnsRecord(RECORD_NAME, differentIssueValue), false),
                        secondary("s3", "APNIC", dnsRecord(RECORD_NAME, differentIssueValue), false)),
                        DcvError.MPIC_CORROBORATION_ERROR));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
    }

    @Test
    void request_builder_makesDefensiveUnmodifiableCopyOfThumbprints() {
        List<String> thumbprints = new java.util.ArrayList<>(List.of(ACTIVE_THUMBPRINT));
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, thumbprints);

        thumbprints.add(HISTORICAL_THUMBPRINT);

        assertEquals(List.of(ACTIVE_THUMBPRINT), request.getAccountThumbprints());
        assertThrows(UnsupportedOperationException.class, () -> request.getAccountThumbprints().add("x"));
    }

    @Test
    void validate_recordWithMultipleAccountUrisOneMatching_reportsMultipleAccountUri() {
        // A record with several accounturi values is never accepted, but if one of them matches we report
        // that (MULTIPLE_ACCOUNT_URI) rather than a plain mismatch.
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        String issueValue = "authority.example; accounturi=" + EXACT_HASH + "; accounturi=https://ca.example/account-hash/sha-256/other";
        DnsRecord record = dnsRecord(RECORD_NAME, issueValue);
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(record));

        AcmeDnsPersistValidationException exception = assertThrows(AcmeDnsPersistValidationException.class, () -> handler.validate(request));

        assertTrue(exception.getErrors().contains(DcvError.MULTIPLE_ACCOUNT_URI));
        assertFalse(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
        assertEquals(request, exception.getAcmeDnsPersistValidationRequest());
    }

    @Test
    void validate_duplicatePolicyParameter_isRejected() {
        // policy=wildcard widens scope, so two policy parameters make the record invalid instead of silently using the first.
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        DnsRecord record = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + EXACT_HASH + "; policy=wildcard; policy=wildcard");
        DnsRecord otherRecord = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + ACCOUNT_HASH_PREFIX + "sha-256/unrelated");
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(List.of(otherRecord, record)));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));

        assertTrue(exception.getErrors().contains(DcvError.MULTIPLE_POLICY));
    }

    @Test
    void validate_unsupportedHashAlgorithm_isReportedAsMalformed() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        DnsRecord record = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + ACCOUNT_HASH_PREFIX + "sha-512/" + EXACT_HASH.substring(EXACT_HASH.lastIndexOf('/') + 1));
        DnsRecord mismatchRecord = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + ACCOUNT_HASH_PREFIX + "sha-256/unrelated");
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(List.of(mismatchRecord, record)));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));

        assertTrue(exception.getErrors().contains(DcvError.INVALID_ISSUE_VALUE_FORMAT));
        assertFalse(exception.getErrors().contains(DcvError.ACCOUNT_URI_MISMATCH));
    }

    @Test
    void validate_unsupportedHashAlgorithmRecordIsFilteredOut_validRecordStillValidates() throws Exception {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        DnsRecord unsupported = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + ACCOUNT_HASH_PREFIX + "sha-512/" + EXACT_HASH.substring(EXACT_HASH.lastIndexOf('/') + 1));
        DnsRecord valid = dnsRecord(RECORD_NAME, "authority.example; accounturi=" + EXACT_HASH);
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(List.of(unsupported, valid)));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, EXACT_HASH))
                .thenReturn(mpicDetails(List.of(unsupported, valid), List.of(
                        secondary("s1", "ARIN", valid, true), secondary("s2", "RIPE", valid, true))));

        AcmeDnsPersistValidationResponse response = handler.validate(request);

        assertEquals(ACTIVE_THUMBPRINT, response.acmePersistentTxtResponse().matchedThumbprint());
    }

    @Test
    void validate_recordWithoutAccountUri_reportsAccountUriRequired() {
        AcmeDnsPersistValidationRequest request = acmeRequest(DcvMethod.BR_3_2_2_4_22, ACCOUNT_URI, List.of(ACTIVE_THUMBPRINT));
        DnsRecord record = dnsRecord(RECORD_NAME, "authority.example");
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(record));

        ValidationException exception = assertThrows(ValidationException.class, () -> handler.validate(request));

        assertTrue(exception.getErrors().contains(DcvError.ACCOUNT_URI_REQUIRED));
    }

    private void stubPrimaryAndFull(DnsRecord primaryRecord, String expectedValueToCheck, List<SecondaryDnsResponse> secondaries) {
        when(mpicDnsService.getPrimaryDnsDetails(RECORD_NAME, DnsType.TXT)).thenReturn(primaryDnsResponse(primaryRecord));
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, expectedValueToCheck))
                .thenReturn(mpicDetails(List.of(primaryRecord), secondaries));
    }

    private List<SecondaryDnsResponse> twoCorroboratingSecondaries(DnsRecord record) {
        return List.of(secondary("s1", "ARIN", record, true), secondary("s2", "RIPE", record, true));
    }

    private static AcmeDnsPersistValidationRequest acmeRequest(DcvMethod method, String accountUri, List<String> thumbprints) {
        return AcmeDnsPersistValidationRequest.builder()
                .domain(DOMAIN)
                .accountUri(accountUri)
                .accountThumbprints(thumbprints)
                .validationState(new ValidationState(DOMAIN, Instant.now(), method))
                .build();
    }

    private static DnsRecord dnsRecord(String name, String value) {
        return new DnsRecord(DnsType.TXT, name, value, 300, 0, "");
    }

    private static PrimaryDnsResponse primaryDnsResponse(DnsRecord record) {
        return primaryDnsResponse(List.of(record));
    }

    private static PrimaryDnsResponse primaryDnsResponse(List<DnsRecord> records) {
        return new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_SUCCESS, DnssecDetails.notChecked(), records, DnsType.TXT, RECORD_NAME, List.of());
    }

    private static SecondaryDnsResponse secondary(String agentId, String rir, DnsRecord record, boolean corroborates) {
        return new SecondaryDnsResponse(agentId,
                AgentStatus.DNS_LOOKUP_SUCCESS,
                rir,
                DnssecDetails.notChecked(),
                corroborates,
                List.of(record),
                List.of(),
                true);
    }

    private static MpicDnsDetails mpicDetails(List<DnsRecord> primaryRecords, List<SecondaryDnsResponse> secondaries) {
        return mpicDetailsWithError(primaryRecords, secondaries, null);
    }

    private static MpicDnsDetails mpicDetailsWithError(List<DnsRecord> primaryRecords, List<SecondaryDnsResponse> secondaries, DcvError dcvError) {
        return new MpicDnsDetails(new MpicDetails(true,
                "primary-agent",
                secondaries.size(),
                secondaries.size(),
                DnssecDetails.notChecked(),
                Map.of(),
                null),
                RECORD_NAME,
                primaryRecords,
                dcvError,
                secondaries);
    }
}
