package com.digicert.validation.methods.dns;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.dns.prepare.DnsPreparation;
import com.digicert.validation.methods.dns.prepare.DnsPreparationResponse;
import com.digicert.validation.methods.dns.validate.DnsValidationHandler;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
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
import java.util.List;
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
                .dnsType(dnsType)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(validationState)
                .build();
    }

    @Test
    void testDnsValidator_validate_HappyPath() throws DcvException {
        DnsValidationResponse dnsValidationResponse = new DnsValidationResponse(true, "8.8.8.8", domain,
                                                        dnsType, randomValue, null, Set.of());

        when(dnsValidationHandler.validate(any(DnsValidationRequest.class))).thenReturn(dnsValidationResponse);

        DomainValidationEvidence evidence = dnsValidator.validate(dnsValidationRequest);

        assertNotNull(evidence);
        assertEquals(domain, evidence.getDomain());
        assertEquals(dnsType, evidence.getDnsType());
        assertEquals("8.8.8.8", evidence.getDnsServer());
        assertEquals(DcvMethod.BR_3_2_2_4_7, evidence.getDcvMethod());
        assertEquals("v2.0.7", DomainValidationEvidence.BR_VERSION);
        assertEquals(randomValue, evidence.getRandomValue());
        assertNotNull(evidence.getValidationDate());
        assertEquals(domain, evidence.getDnsRecordName());
    }

    @Test
    void testDnsValidator_validate_FalseDnsValidation() {
        DnsValidationResponse dnsValidationResponse = new DnsValidationResponse(false, "8.8.8.8", domain,
                                                        dnsType, randomValue, null, Set.of(DcvError.INVALID_DNS_TYPE));

        when(dnsValidationHandler.validate(any(DnsValidationRequest.class))).thenReturn(dnsValidationResponse);

        ValidationException exception = assertThrows(ValidationException.class, () -> dnsValidator.validate(dnsValidationRequest));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_DNS_TYPE));
        verify(dnsValidationHandler, times(1)).validate(any(DnsValidationRequest.class));
    }

    static Stream<Arguments> provideInvalidDnsValidationResponse() {
        return Stream.of(
                Arguments.of(null, "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, Instant.now(),
                        List.of("Domain is required", "Secret Type is required", "Domain in Validation State is required")),
                Arguments.of("example.com", null, DnsType.CNAME, DcvMethod.BR_3_2_2_4_7, Instant.now(),
                        List.of("Secret Type is required")),
                Arguments.of("example.com", "1234abcd", null, DcvMethod.BR_3_2_2_4_7, Instant.now(),
                        List.of("DNS Record Type is required", "Secret Type is required")),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, null, Instant.now(),
                        List.of("Secret Type is required", "Invalid DCV Method")),
                Arguments.of("example.com", "1234abcd", DnsType.TXT, DcvMethod.BR_3_2_2_4_7, (null),
                        List.of("Secret Type is required", "Prepare Time is required"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidDnsValidationResponse")
    void testDnsValidator_validate_InvalidDnsValidationResponse(String domain, String randomValue, DnsType dnsType,
                                                                DcvMethod dcvMethod, Instant prepareTime, List<String> errors) {
        ValidationState invalidValidationState = new ValidationState(domain, prepareTime, dcvMethod);
        DnsValidationRequest invalidDnsValidationRequest = DnsValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .dnsType(dnsType)
                .validationState(invalidValidationState)
                .build();

        assertThrows(InputException.class, () -> dnsValidator.validate(invalidDnsValidationRequest));
    }

    @Test
    void testDnsValidator_validate_ExpiredValidationState() {
        ValidationState expiredValidationState = new ValidationState(domain, Instant.now().minus(Duration.ofDays(31)), DcvMethod.BR_3_2_2_4_7);
        DnsValidationRequest expiredDnsValidationRequest = DnsValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .dnsType(dnsType)
                .challengeType(ChallengeType.RANDOM_VALUE)
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
                Arguments.of("example.com", DnsType.TXT, null, DcvError.SECRET_TYPE_REQUIRED)
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
}