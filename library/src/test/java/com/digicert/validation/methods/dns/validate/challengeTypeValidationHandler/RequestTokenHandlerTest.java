package com.digicert.validation.methods.dns.validate.challengeTypeValidationHandler;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRequestTokenData;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.methods.dns.validate.handlers.RequestTokenHandler;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RequestTokenHandlerTest {

    @Mock
    private MpicDnsService mpicDnsService;

    @Mock
    private RequestTokenValidator requestTokenValidator;

    private RequestTokenHandler handler;

    private static final String DOMAIN = "example.com";
    private static final String LABEL = "_dnsauth.";
    private static final String TOKEN = "valid-token";

    @BeforeEach
    void setUp() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder().dnsDomainLabel(LABEL).build();

        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        doReturn(requestTokenValidator).when(dcvContext).get(RequestTokenValidator.class);
        handler = new RequestTokenHandler(dcvContext);
    }

    @Test
    void validate_usesLabelPath_whenPrimaryAndDnsRecordsMatch() throws Exception {
        DnsValidationRequest request = requestTokenRequest("", DcvMethod.BR_3_2_2_4_7, true);
        String labeledDomain = LABEL + DOMAIN;

        PrimaryDnsResponse primary = primaryResponse(labeledDomain, List.of(dnsRecord(labeledDomain, "candidate")));
        when(mpicDnsService.getPrimaryDnsDetails(labeledDomain, DnsType.TXT)).thenReturn(primary);
        when(requestTokenValidator.validate(request.getRequestTokenData(), "candidate")).thenReturn(success(TOKEN));
        when(mpicDnsService.getDnsDetails(labeledDomain, DnsType.TXT, TOKEN))
                .thenReturn(mpicDetails(labeledDomain, List.of(dnsRecord(labeledDomain, TOKEN)), null));
        when(requestTokenValidator.validate(request.getRequestTokenData(), TOKEN)).thenReturn(success(TOKEN));

        DnsValidationResponse response = handler.validate(request);

        assertTrue(response.isValid());
        assertEquals(labeledDomain, response.dnsRecordName());
        assertEquals(TOKEN, response.validRequestToken());
        verify(mpicDnsService).getPrimaryDnsDetails(labeledDomain, DnsType.TXT);
        verify(mpicDnsService, never()).getPrimaryDnsDetails(DOMAIN, DnsType.TXT);
    }

    @Test
    void validate_fallsBackToUnlabeled_whenLabeledPathFails() throws Exception {
        DnsValidationRequest request = requestTokenRequest("", DcvMethod.BR_3_2_2_4_7, true);
        String labeledDomain = LABEL + DOMAIN;

        PrimaryDnsResponse labeledPrimary = primaryResponse(labeledDomain, List.of(dnsRecord(labeledDomain, "bad-candidate")));
        PrimaryDnsResponse barePrimary = primaryResponse(DOMAIN, List.of(dnsRecord(DOMAIN, "bare-candidate")));

        when(mpicDnsService.getPrimaryDnsDetails(labeledDomain, DnsType.TXT)).thenReturn(labeledPrimary);
        when(mpicDnsService.getPrimaryDnsDetails(DOMAIN, DnsType.TXT)).thenReturn(barePrimary);

        when(requestTokenValidator.validate(request.getRequestTokenData(), "bad-candidate")).thenReturn(failure(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        when(requestTokenValidator.validate(request.getRequestTokenData(), "bare-candidate")).thenReturn(success(TOKEN));

        when(mpicDnsService.getDnsDetails(DOMAIN, DnsType.TXT, TOKEN))
                .thenReturn(mpicDetails(DOMAIN, List.of(dnsRecord(DOMAIN, TOKEN)), null));
        when(requestTokenValidator.validate(request.getRequestTokenData(), TOKEN)).thenReturn(success(TOKEN));

        DnsValidationResponse response = handler.validate(request);

        assertTrue(response.isValid());
        assertEquals(DOMAIN, response.dnsRecordName());
        assertEquals(TOKEN, response.validRequestToken());
        verify(mpicDnsService).getPrimaryDnsDetails(labeledDomain, DnsType.TXT);
        verify(mpicDnsService).getPrimaryDnsDetails(DOMAIN, DnsType.TXT);
    }

    @Test
    void validate_returnsInvalidResponse_whenBothPrimaryLookupsFail() throws Exception {
        DnsValidationRequest request = requestTokenRequest("", DcvMethod.BR_3_2_2_4_7, true);
        String labeledDomain = LABEL + DOMAIN;

        when(mpicDnsService.getPrimaryDnsDetails(labeledDomain, DnsType.TXT)).thenReturn(null);
        when(mpicDnsService.getPrimaryDnsDetails(DOMAIN, DnsType.TXT)).thenReturn(null);
        when(mpicDnsService.mapToDcvErrorOrNull(null, MpicStatus.VALUE_NOT_FOUND)).thenReturn(DcvError.MPIC_INVALID_RESPONSE);

        DnsValidationResponse response = handler.validate(request);

        assertFalse(response.isValid());
        assertTrue(response.errors().contains(DcvError.MPIC_INVALID_RESPONSE));
        assertNull(response.validRequestToken());
    }

    static Stream<Arguments> validateRequestTokenScenarios() {
        return Stream.of(
                Arguments.of(List.of("candidate"), List.of(success(TOKEN)), Optional.of(TOKEN), Set.of()),
                Arguments.of(List.of("candidate"), List.of(failure(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND)), Optional.empty(), Set.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND)),
                Arguments.of(List.of(), List.of(), Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND))
        );
    }

    @ParameterizedTest
    @MethodSource("validateRequestTokenScenarios")
    void validateRequestToken_behavesAsExpected(List<String> values,
                                                List<ChallengeValidationResponse> validatorResponses,
                                                Optional<String> expectedValue,
                                                Set<DcvError> expectedErrors) {
        DnsValidationRequest request = requestTokenRequest("", DcvMethod.BR_3_2_2_4_7, true);
        for (int i = 0; i < values.size(); i++) {
            when(requestTokenValidator.validate(request.getRequestTokenData(), values.get(i))).thenReturn(validatorResponses.get(i));
        }

        ChallengeValidationResponse response = handler.validateRequestToken(values, request);

        assertEquals(expectedValue, response.challengeValue());
        assertEquals(expectedErrors, response.errors());
    }

    @ParameterizedTest
    @MethodSource("invalidRequestScenarios")
    void validate_throwsForInvalidRequest(DnsValidationRequest request, DcvError expectedError) {
        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));
        assertTrue(exception.getErrors().contains(expectedError));
        verifyNoInteractions(mpicDnsService);
    }

    static Stream<Arguments> invalidRequestScenarios() {
        return Stream.of(
                Arguments.of(requestTokenRequest("", DcvMethod.BR_3_2_2_4_22, true), DcvError.INVALID_DCV_METHOD),
                Arguments.of(requestTokenRequest("", DcvMethod.BR_3_2_2_4_7, false), DcvError.REQUEST_TOKEN_DATA_REQUIRED)
        );
    }

    private static DnsValidationRequest requestTokenRequest(String domainLabel, DcvMethod method, boolean includeRequestTokenData) {
        DnsValidationRequest.DnsValidationRequestBuilder builder = DnsValidationRequest.builder()
                .domain(DOMAIN)
                .dnsType(DnsType.TXT)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .domainLabel(domainLabel)
                .validationState(new ValidationState(DOMAIN, Instant.now(), method));
        if (includeRequestTokenData) {
            builder.requestTokenData(new BasicRequestTokenData("hash-key", "hash-value"));
        }
        return builder.build();
    }

    private static PrimaryDnsResponse primaryResponse(String domain, List<DnsRecord> records) {
        return new PrimaryDnsResponse("primary-agent",
                AgentStatus.DNS_LOOKUP_SUCCESS,
                DnssecDetails.notChecked(),
                records,
                DnsType.TXT,
                domain,
                null);
    }

    private static DnsRecord dnsRecord(String name, String value) {
        return new DnsRecord(DnsType.TXT, name, value, 300, 0, "");
    }

    private static MpicDnsDetails mpicDetails(String domain, List<DnsRecord> records, DcvError error) {
        return new MpicDnsDetails(new MpicDetails(true,
                "primary-agent",
                2,
                2,
                DnssecDetails.notChecked(),
                Map.of("secondary-1", true),
                null),
                domain,
                records,
                error);
    }

    private static ChallengeValidationResponse success(String value) {
        return new ChallengeValidationResponse(Optional.of(value), Set.of());
    }

    private static ChallengeValidationResponse failure(DcvError error) {
        return new ChallengeValidationResponse(Optional.empty(), Set.of(error));
    }
}
