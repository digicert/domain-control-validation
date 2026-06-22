package com.digicert.validation.methods.dns.validate.challengeTypeValidationHandler;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.methods.dns.validate.handlers.RandomValueHandler;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.random.RandomValueVerifier;
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
class RandomValueHandlerTest {

    @Mock
    private MpicDnsService mpicDnsService;

    @Mock
    private RandomValueValidator randomValueValidator;

    @Mock
    private RandomValueVerifier randomValueVerifier;

    private RandomValueHandler handler;

    private static final String DOMAIN = "example.com";
    private static final String LABEL = "_dnsauth.";
    private static final String RANDOM_VALUE = "some-really-long-random-value";

    @BeforeEach
    void setUp() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsDomainLabel(LABEL)
                .build();

        DcvContext dcvContext = spy(new DcvContext(config));
        doReturn(mpicDnsService).when(dcvContext).get(MpicDnsService.class);
        doReturn(randomValueValidator).when(dcvContext).get(RandomValueValidator.class);
        doReturn(randomValueVerifier).when(dcvContext).get(RandomValueVerifier.class);
        handler = new RandomValueHandler(dcvContext);
    }

    @Test
    void validate_usesLabelFirst_whenLabelHasMatch() throws Exception {
        DnsValidationRequest request = randomValueRequest("", DcvMethod.BR_3_2_2_4_7);
        String labeledDomain = "_dnsauth." + DOMAIN;

        MpicDnsDetails labeledDetails = mpicDetails(labeledDomain, List.of(dnsRecord(labeledDomain, RANDOM_VALUE)), null);
        when(mpicDnsService.getDnsDetails(labeledDomain, DnsType.TXT, RANDOM_VALUE)).thenReturn(labeledDetails);
        when(randomValueValidator.validate(RANDOM_VALUE, RANDOM_VALUE)).thenReturn(success(RANDOM_VALUE));

        DnsValidationResponse response = handler.validate(request);

        assertTrue(response.isValid());
        assertEquals(labeledDomain, response.dnsRecordName());
        assertEquals(RANDOM_VALUE, response.validRandomValue());
        verify(mpicDnsService).getDnsDetails(labeledDomain, DnsType.TXT, RANDOM_VALUE);
        verify(mpicDnsService, never()).getDnsDetails(DOMAIN, DnsType.TXT, RANDOM_VALUE);
    }

    @Test
    void validate_fallsBackToUnlabeled_whenLabelFails() throws Exception {
        DnsValidationRequest request = randomValueRequest("", DcvMethod.BR_3_2_2_4_7);
        String labeledDomain = "_dnsauth." + DOMAIN;

        when(mpicDnsService.getDnsDetails(labeledDomain, DnsType.TXT, RANDOM_VALUE))
                .thenReturn(mpicDetails(labeledDomain, List.of(), DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        when(mpicDnsService.getDnsDetails(DOMAIN, DnsType.TXT, RANDOM_VALUE))
                .thenReturn(mpicDetails(DOMAIN, List.of(dnsRecord(DOMAIN, RANDOM_VALUE)), null));
        when(randomValueValidator.validate(RANDOM_VALUE, RANDOM_VALUE)).thenReturn(success(RANDOM_VALUE));

        DnsValidationResponse response = handler.validate(request);

        assertTrue(response.isValid());
        assertEquals(DOMAIN, response.dnsRecordName());
        assertEquals(RANDOM_VALUE, response.validRandomValue());
        verify(mpicDnsService).getDnsDetails(labeledDomain, DnsType.TXT, RANDOM_VALUE);
        verify(mpicDnsService).getDnsDetails(DOMAIN, DnsType.TXT, RANDOM_VALUE);
    }

    @Test
    void validate_returnsMergedErrors_whenBothLookupsFail() throws Exception {
        DnsValidationRequest request = randomValueRequest("", DcvMethod.BR_3_2_2_4_7);
        String labeledDomain = "_dnsauth." + DOMAIN;

        when(mpicDnsService.getDnsDetails(labeledDomain, DnsType.TXT, RANDOM_VALUE))
                .thenReturn(mpicDetails(labeledDomain, List.of(dnsRecord(labeledDomain, "not-match")), null));
        when(mpicDnsService.getDnsDetails(DOMAIN, DnsType.TXT, RANDOM_VALUE))
                .thenReturn(mpicDetails(DOMAIN, List.of(), DcvError.DNS_LOOKUP_IO_EXCEPTION));
        when(randomValueValidator.validate(RANDOM_VALUE, "not-match")).thenReturn(failure(DcvError.RANDOM_VALUE_NOT_FOUND));

        DnsValidationResponse response = handler.validate(request);

        assertFalse(response.isValid());
        assertTrue(response.errors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
        assertTrue(response.errors().contains(DcvError.DNS_LOOKUP_IO_EXCEPTION));
    }

    static Stream<Arguments> validateRandomValueScenarios() {
        return Stream.of(
                Arguments.of(List.of("body-1"), List.of(failure(DcvError.RANDOM_VALUE_NOT_FOUND)), Optional.empty(), Set.of(DcvError.RANDOM_VALUE_NOT_FOUND)),
                Arguments.of(List.of("body-1", "body-2"), List.of(failure(DcvError.RANDOM_VALUE_NOT_FOUND), success(RANDOM_VALUE)), Optional.of(RANDOM_VALUE), Set.of()),
                Arguments.of(List.of(), List.of(), Optional.empty(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND))
        );
    }

    @ParameterizedTest
    @MethodSource("validateRandomValueScenarios")
    void validateRandomValue_behavesAsExpected(List<String> values,
                                               List<ChallengeValidationResponse> validatorResponses,
                                               Optional<String> expectedValue,
                                               Set<DcvError> expectedErrors) {
        DnsValidationRequest request = randomValueRequest("", DcvMethod.BR_3_2_2_4_7);
        for (int i = 0; i < values.size(); i++) {
            when(randomValueValidator.validate(RANDOM_VALUE, values.get(i))).thenReturn(validatorResponses.get(i));
        }

        ChallengeValidationResponse response = handler.validateRandomValue(values, request);

        assertEquals(expectedValue, response.challengeValue());
        assertEquals(expectedErrors, response.errors());
    }

    @Test
    void validate_throwsForInvalidValidationState() {
        DnsValidationRequest request = randomValueRequest("", DcvMethod.BR_3_2_2_4_22);

        InputException exception = assertThrows(InputException.class, () -> handler.validate(request));

        assertTrue(exception.getErrors().contains(DcvError.INVALID_DCV_METHOD));
        verifyNoInteractions(mpicDnsService);
    }

    private static DnsValidationRequest randomValueRequest(String domainLabel, DcvMethod method) {
        return DnsValidationRequest.builder()
                .domain(DOMAIN)
                .dnsType(DnsType.TXT)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .randomValue(RANDOM_VALUE)
                .domainLabel(domainLabel)
                .validationState(new ValidationState(DOMAIN, Instant.now(), method))
                .build();
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
