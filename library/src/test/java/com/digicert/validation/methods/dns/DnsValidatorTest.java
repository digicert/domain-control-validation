package com.digicert.validation.methods.dns;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.dns.prepare.DnsPreparation;
import com.digicert.validation.methods.dns.prepare.DnsPreparationResponse;
import com.digicert.validation.methods.dns.validate.DnsValidationHandler;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.mpic.MpicDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DnsValidatorTest {

    String domain;
    String randomValue;
    DnsType dnsType;

    ValidationState validationState;
    DnsValidationRequest dnsValidationRequest;

    @Mock
    DnsValidationHandler dnsValidationHandler;

    DnsValidator dnsValidator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Use a spy to hand the DnsValidator a mocked DnsValidationHandler
        DcvContext dcvContext = spy(new DcvContext());
        doCallRealMethod().when(dcvContext).get(any());
        doReturn(dnsValidationHandler).when(dcvContext).get(DnsValidationHandler.class);

        dnsValidator = new DnsValidator(dcvContext);

        domain = "example.com";
        randomValue = "some-really-long-random-value";
        dnsType = DnsType.TXT;

        validationState = new ValidationState(domain, Instant.now(), DcvMethod.BR_3_2_2_4_7);
        dnsValidationRequest = DnsValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .dnsType(dnsType)
                .validationState(validationState)
                .build();
    }

    @Test
    void testDnsValidator_validate_HappyPath() throws DcvException {
        DnsValidationResponse dnsValidationResponse = new DnsValidationResponse(true, getMpicDetails(), domain, domain,
                                                        dnsType, randomValue, null, Set.of());

        when(dnsValidationHandler.validate(any(DnsValidationRequest.class))).thenReturn(dnsValidationResponse);

        DomainValidationEvidence evidence = dnsValidator.validate(dnsValidationRequest);

        assertNotNull(evidence);
        assertEquals(domain, evidence.getDomain());
        assertEquals(dnsType, evidence.getDnsType());
        assertNotNull(evidence.getMpicDetails());
        assertEquals("primary-agent", evidence.getMpicDetails().primaryAgentId());
        assertEquals(DcvMethod.BR_3_2_2_4_7, evidence.getDcvMethod());
        assertEquals("v2.1.1", DomainValidationEvidence.BR_VERSION);
        assertEquals(randomValue, evidence.getRandomValue());
        assertNotNull(evidence.getValidationDate());
        assertEquals(domain, evidence.getDnsRecordName());
    }

    @Test
    void testDnsValidator_validate_FalseDnsValidation() {
        DnsValidationResponse dnsValidationResponse = new DnsValidationResponse(false, getMpicDetails(), domain, domain,
                                                        dnsType, randomValue, null, Set.of(DcvError.INVALID_DNS_TYPE));

        when(dnsValidationHandler.validate(any(DnsValidationRequest.class))).thenReturn(dnsValidationResponse);

        ValidationException exception = assertThrows(ValidationException.class, () -> dnsValidator.validate(dnsValidationRequest));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_DNS_TYPE));
        verify(dnsValidationHandler, times(1)).validate(any(DnsValidationRequest.class));
    }

    static Stream<Arguments> provideInvalidDnsValidationResponse() {
        return Stream.of(
                // domain, randomValue, dnsType, dcvMethod, prepareTime, dnsDomainLabel, challengeType, expectedError
                Arguments.of(null, "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.DOMAIN_REQUIRED),
                Arguments.of("example.com", null, DnsType.CNAME, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.RANDOM_VALUE_REQUIRED),
                Arguments.of("example.com", null, DnsType.CAA, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.RANDOM_VALUE_REQUIRED),
                Arguments.of("example.com", null, DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.REQUEST_TOKEN, DcvError.REQUEST_TOKEN_DATA_REQUIRED),
                Arguments.of("example.com", "1234abcd", null, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.DNS_TYPE_REQUIRED),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, null, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.VALIDATION_STATE_DCV_METHOD_REQUIRED),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, (null), "", ChallengeType.RANDOM_VALUE, DcvError.VALIDATION_STATE_PREPARE_TIME_REQUIRED),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), "dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.DNS_DOMAIN_LABEL_INVALID),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), " ", ChallengeType.RANDOM_VALUE, DcvError.DNS_DOMAIN_LABEL_INVALID),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_invalid.dot", ChallengeType.RANDOM_VALUE, DcvError.DNS_DOMAIN_LABEL_INVALID),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", null, DcvError.CHALLENGE_TYPE_REQUIRED),
                Arguments.of("example.com", "1234abcd", DnsType.A, DcvMethod.BR_3_2_2_4_7, Instant.now(), "_dnsauth.", ChallengeType.RANDOM_VALUE, DcvError.INVALID_DNS_TYPE)
                );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidDnsValidationResponse")
    void testDnsValidator_validate_InvalidDnsValidationResponse(String domain,
                                                                String randomValue,
                                                                DnsType dnsType,
                                                                DcvMethod dcvMethod,
                                                                Instant prepareTime,
                                                                String dnsDomainLabel,
                                                                ChallengeType challengeType,
                                                                DcvError expectedError) {
        ValidationState validationState = new ValidationState(domain, prepareTime, dcvMethod);
        DnsValidationRequest invalidDnsValidationRequest = DnsValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .challengeType(challengeType)
                .domainLabel(dnsDomainLabel)
                .dnsType(dnsType)
                .validationState(validationState)
                .build();

        InputException exception = assertThrows(InputException.class, () -> dnsValidator.validate(invalidDnsValidationRequest));
        assertEquals(1, exception.getErrors().size(), "Expected exactly one error but got: " + exception.getErrors());
        assertTrue(exception.getErrors().contains(expectedError), "expected error=" + expectedError + " errors=" + exception.getErrors());
    }

    @Test
    void testDnsValidator_validate_ExpiredValidationState() {
        ValidationState expiredValidationState = new ValidationState(domain, Instant.now().minus(Duration.ofDays(31)), DcvMethod.BR_3_2_2_4_7);
        DnsValidationRequest expiredDnsValidationRequest = DnsValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .dnsType(dnsType)
                .validationState(expiredValidationState)
                .build();

        assertThrows(ValidationException.class, () -> dnsValidator.validate(expiredDnsValidationRequest));
    }

    @Test
    void testDnsValidator_prepare_HappyPath() throws DcvException {
        DnsPreparation dnsPreparation = new DnsPreparation(domain, DnsType.TXT, ChallengeType.RANDOM_VALUE);

        DnsPreparationResponse dnsPreparationResponse = dnsValidator.prepare(dnsPreparation);
        validationState = dnsPreparationResponse.getValidationState();

        assertEquals(domain, dnsPreparationResponse.getDomain());
        assertNotNull(dnsPreparationResponse.getRandomValue());
        assertTrue(dnsPreparationResponse.getAllowedFqdns().contains(domain));
        assertEquals(DnsType.TXT, dnsPreparationResponse.getDnsType());

        assertEquals(domain, validationState.domain());
        assertNotNull(validationState.prepareTime());
        assertEquals(DcvMethod.BR_3_2_2_4_7, validationState.dcvMethod());
    }

    static Stream<Arguments> provideInvalidDnsPreparation() {
        return Stream.of(
                Arguments.of(null, DnsType.TXT, ChallengeType.RANDOM_VALUE, DcvError.DOMAIN_REQUIRED),
                Arguments.of("example.com", null, ChallengeType.RANDOM_VALUE, DcvError.DNS_TYPE_REQUIRED),
                Arguments.of("example.com", DnsType.TXT, null, DcvError.CHALLENGE_TYPE_REQUIRED)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidDnsPreparation")
    void testDnsValidator_prepare_InvalidDnsPreparation(String domain, DnsType dnsType, ChallengeType challengeType,
                                                        DcvError dcvError) {
        DnsPreparation invalidDnsPreparation = new DnsPreparation(domain, dnsType, challengeType);

        DcvException exception = assertThrows(DcvException.class, () ->
                dnsValidator.prepare(invalidDnsPreparation));

        assertTrue(exception.getErrors().contains(dcvError), "expected: " + dcvError + " but got: " + exception.getErrors());
    }

    private static MpicDetails getMpicDetails() {
        return new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-agent-id", true));
    }
}
