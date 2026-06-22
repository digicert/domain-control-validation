package com.digicert.validation.methods.dns.validate.challengeTypeValidationHandler;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.methods.dns.validate.handlers.PersistentValueHandler;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PersistentValueHandlerTest {

    @Mock
    private MpicDnsService mpicDnsService;

    private PersistentValueHandler handler;

    private static final String DOMAIN = "example.com";
    private static final String ACCOUNT_URI = "https://authority.example/acct/123";
    private static final String RECORD_NAME = "_validation-persist.example.com";

    @BeforeEach
    void setUp() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .allowedIssuerDomains(List.of("authority.example"))
                .build();

        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        handler = new PersistentValueHandler(dcvContext);
    }

    @Test
    void validate_throwsIllegalStateExceptionWhenIssuerDomainsIsEmpty() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                                          .build();

        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        PersistentValueHandler handlerWithNoAllowedIssuers = new PersistentValueHandler(dcvContext);
        assertThrows(IllegalStateException.class, () -> handlerWithNoAllowedIssuers.validate(null));
    }

    static Stream<Arguments> happyPathScenarios() {
        return Stream.of(
                Arguments.of("happy path with lowercase issuer domain", "authority.example"),
                Arguments.of("TC-34 uppercase issuer domain in TXT", "AUTHORITY.EXAMPLE")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("happyPathScenarios")
    void validate_happyPath_requiresCorroborationAndReturnsValid(String description, String issuerDomain) throws Exception {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, ACCOUNT_URI);
        String issueValue = issuerDomain + "; accounturi=" + ACCOUNT_URI + "; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond();

        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, issueValue);
        SecondaryDnsResponse secondaryOne = secondary("secondary-1", "ARIN", dnsRecord(RECORD_NAME, issueValue));
        SecondaryDnsResponse secondaryTwo = secondary("secondary-2", "RIPE", dnsRecord(RECORD_NAME, issueValue));

        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, ACCOUNT_URI))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(secondaryOne, secondaryTwo)));

        DnsValidationResponse response = handler.validate(request);

        assertTrue(response.isValid());
        assertTrue(response.errors().isEmpty());
        assertNotNull(response.persistentTxtResponse());
        assertEquals(ACCOUNT_URI, response.persistentTxtResponse().accountUri());
    }

    @Test
    void validate_failsWhenPrimaryRecordMissing() throws Exception {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, ACCOUNT_URI);
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, ACCOUNT_URI))
                .thenReturn(mpicDetails(List.of(), List.of()));

        DnsValidationResponse response = handler.validate(request);

        assertFalse(response.isValid());
        assertTrue(response.errors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }

    @Test
    void validate_returnsMpicLookupErrorWithoutParsingTxtRecords() throws Exception {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, ACCOUNT_URI);
        String validIssueValue = "authority.example; accounturi=" + ACCOUNT_URI + "; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond();
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, ACCOUNT_URI))
                .thenReturn(mpicDetails(List.of(dnsRecord(RECORD_NAME, validIssueValue)), List.of(), DcvError.DNS_LOOKUP_IO_EXCEPTION));

        DnsValidationResponse response = handler.validate(request);

        assertFalse(response.isValid());
        assertEquals(Set.of(DcvError.DNS_LOOKUP_IO_EXCEPTION), response.errors());
        assertNull(response.persistentTxtResponse());
    }

    @Test
    void validate_returnsCorroborationErrorWhenCorroborationFailsWithoutSecondaryParseErrors() throws Exception {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, ACCOUNT_URI);
        String validIssueValue = "authority.example; accounturi=" + ACCOUNT_URI + "; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond();

        DnsRecord primaryRecord = dnsRecord(RECORD_NAME, validIssueValue);
        SecondaryDnsResponse secondaryOne = secondary("secondary-1", "ARIN", dnsRecord(RECORD_NAME, validIssueValue));
        SecondaryDnsResponse secondaryTwo = secondary("secondary-2", "ARIN", dnsRecord(RECORD_NAME, validIssueValue));
        SecondaryDnsResponse secondaryThree = secondary("secondary-3", "ARIN", dnsRecord(RECORD_NAME, validIssueValue));

        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, ACCOUNT_URI))
                .thenReturn(mpicDetails(List.of(primaryRecord), List.of(secondaryOne, secondaryTwo, secondaryThree)));

        DnsValidationResponse response = handler.validate(request);

        assertFalse(response.isValid());
        assertEquals(Set.of(DcvError.MPIC_CORROBORATION_ERROR), response.errors());
    }

    static Stream<Arguments> invalidTxtRecordTestCases() {
        String validAccount = ACCOUNT_URI;
        return Stream.of(
                Arguments.of("invalid issuer domain not allowed", "bad-authority.example; accounturi=" + validAccount, DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED),
                Arguments.of("account URI mismatch", "authority.example; accounturi=https://authority.example/acct/999", DcvError.ACCOUNT_URI_MISMATCH),
                Arguments.of("negative persistUntil", "authority.example; accounturi=" + validAccount + "; persistUntil=-1", DcvError.INVALID_PERSIST_UNTIL),
                Arguments.of("duplicate persistUntil parameters", "authority.example; accounturi=" + validAccount + "; persistUntil=1; persistUntil=2", DcvError.MULTIPLE_PERSIST_UNTIL),
                Arguments.of("TC-16 expired persistUntil in past", "authority.example; accounturi=" + validAccount + "; persistUntil=1000000000", DcvError.PERSISTENT_RECORD_EXPIRED),
                Arguments.of("TC-19 missing accounturi parameter", "authority.example; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond(), DcvError.ACCOUNT_URI_REQUIRED),
                Arguments.of("TC-20 duplicate accounturi parameters", "authority.example; accounturi=" + validAccount + "; accounturi=https://authority.example/acct/999; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond(), DcvError.MULTIPLE_ACCOUNT_URI),
                Arguments.of("TC-21 duplicate persistUntil parameters", "authority.example; accounturi=" + validAccount + "; persistUntil=1; persistUntil=2", DcvError.MULTIPLE_PERSIST_UNTIL),
                Arguments.of("TC-22 non-numeric persistUntil", "authority.example; accounturi=" + validAccount + "; persistUntil=not-a-number", DcvError.INVALID_PERSIST_UNTIL),
                Arguments.of("persistUntil larger than Instant max", "authority.example; accounturi=" + validAccount + "; persistUntil=" + Long.MAX_VALUE, DcvError.INVALID_PERSIST_UNTIL),
                Arguments.of("TC-24 invalid LDH issuer domain", "auth_1.example; accounturi=" + validAccount + "; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond(), DcvError.INVALID_ISSUE_VALUE_FORMAT),
                Arguments.of("TC-25 parameter without equals sign", "authority.example; accounturi; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond(), DcvError.INVALID_ISSUE_VALUE_FORMAT),
                Arguments.of("TC-26 space in parameter value", "authority.example; accounturi=bad value; persistUntil=" + Instant.now().plusSeconds(600).getEpochSecond(), DcvError.INVALID_ISSUE_VALUE_FORMAT),
                Arguments.of("TC-32 persistUntil exactly now", "authority.example; accounturi=" + validAccount + "; persistUntil=" + Instant.now().getEpochSecond(), DcvError.PERSISTENT_RECORD_EXPIRED)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidTxtRecordTestCases")
    void validate_failsWithExpectedIssueValueError(String description, String issueValue, DcvError expectedError) throws Exception {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, ACCOUNT_URI);
        when(mpicDnsService.getDnsDetails(RECORD_NAME, DnsType.TXT, ACCOUNT_URI))
                .thenReturn(mpicDetails(List.of(dnsRecord(RECORD_NAME, issueValue)), List.of()));

        DnsValidationResponse response = assertDoesNotThrow(() -> handler.validate(request));

        assertFalse(response.isValid());
        assertTrue(response.errors().contains(expectedError));
    }

    static Stream<Arguments> invalidRequestScenarios() {
        return Stream.of(
                Arguments.of("invalid dcv method", persistentRequest(DcvMethod.BR_3_2_2_4_7, DnsType.TXT, ACCOUNT_URI), DcvError.INVALID_DCV_METHOD),
                Arguments.of("invalid dns type", persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.CNAME, ACCOUNT_URI), DcvError.INVALID_DNS_TYPE),
                Arguments.of("missing account URI in request", persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, null), DcvError.ACCOUNT_URI_REQUIRED)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidRequestScenarios")
    void validate_throwsForInvalidRequest(String description, DnsValidationRequest request, DcvError expectedError) {
        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(expectedError));
        verifyNoInteractions(mpicDnsService);
    }

    @Test
    void validate_throwsForInvalidAccountUri() {
        DnsValidationRequest request = persistentRequest(DcvMethod.BR_3_2_2_4_22, DnsType.TXT, "http://[");

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_ACCOUNT_URI));
        verifyNoInteractions(mpicDnsService);
    }

    private static DnsValidationRequest persistentRequest(DcvMethod method, DnsType dnsType, String accountUri) {
        return DnsValidationRequest.builder()
                .domain(DOMAIN)
                .dnsType(dnsType)
                .challengeType(ChallengeType.PERSISTENT_VALUE)
                .accountUri(accountUri)
                .validationState(new ValidationState(DOMAIN, Instant.now(), method))
                .build();
    }

    private static DnsRecord dnsRecord(String name, String value) {
        return new DnsRecord(DnsType.TXT, name, value, 300, 0, "");
    }

    private static SecondaryDnsResponse secondary(String agentId, String rir, DnsRecord record) {
        return new SecondaryDnsResponse(agentId,
                AgentStatus.DNS_LOOKUP_SUCCESS,
                rir,
                DnssecDetails.notChecked(),
                true,
                List.of(record),
                List.of(),
                true);
    }

    private static MpicDnsDetails mpicDetails(List<DnsRecord> primaryRecords, List<SecondaryDnsResponse> secondaries) {
        return mpicDetails(primaryRecords, secondaries, null);
    }

    private static MpicDnsDetails mpicDetails(List<DnsRecord> primaryRecords,
                                              List<SecondaryDnsResponse> secondaries,
                                              DcvError dcvError) {
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
