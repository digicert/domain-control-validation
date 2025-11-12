package com.digicert.validation.methods.acme;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.*;
import com.digicert.validation.exceptions.AcmeValidationException;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.acme.prepare.AcmePreparation;
import com.digicert.validation.methods.acme.prepare.AcmePreparationResponse;
import com.digicert.validation.methods.acme.validate.AcmeValidationHandler;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import com.digicert.validation.methods.acme.validate.AcmeValidationResponse;
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
class AcmeValidatorTest {

    String domain;
    String randomValue;

    ValidationState validationState;
    AcmeValidationRequest acmeValidationRequest;

    @Mock
    AcmeValidationHandler acmeValidationHandler;

    AcmeValidator acmeValidator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Use a spy to hand the AcmeValidator a mocked AcmeValidationHandler
        DcvContext dcvContext = spy(new DcvContext());
        doCallRealMethod().when(dcvContext).get(any());
        doReturn(acmeValidationHandler).when(dcvContext).get(AcmeValidationHandler.class);

        acmeValidator = new AcmeValidator(dcvContext);

        domain = "example.com";
        randomValue = "some-really-long-random-value";

        validationState = new ValidationState(domain, Instant.now(), DcvMethod.UNKNOWN);
        acmeValidationRequest = AcmeValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .acmeThumbprint("acme-thumbprint")
                .acmeType(AcmeType.ACME_DNS_01)
                .validationState(validationState)
                .build();
    }

    @Test
    void testAcmeValidator_validate_HappyPath() throws DcvException {
        AcmeValidationResponse acmeValidationResponse = new AcmeValidationResponse(getMpicDetails(), "_acme-challenge." + domain, null);

        when(acmeValidationHandler.validate(any(AcmeValidationRequest.class))).thenReturn(acmeValidationResponse);

        DomainValidationEvidence evidence = acmeValidator.validate(acmeValidationRequest);

        assertNotNull(evidence);
        assertEquals(domain, evidence.getDomain());
        assertEquals(DnsType.TXT, evidence.getDnsType());
        assertNotNull(evidence.getMpicDetails());
        assertEquals("primary-agent", evidence.getMpicDetails().primaryAgentId());
        assertEquals(DcvMethod.BR_3_2_2_4_7, evidence.getDcvMethod());
        assertEquals("v2.1.1", DomainValidationEvidence.BR_VERSION);
        assertEquals(randomValue, evidence.getRandomValue());
        assertNotNull(evidence.getValidationDate());
        assertEquals("_acme-challenge." + domain, evidence.getDnsRecordName());
    }

    @Test
    void testAcmeValidator_validate_FalseDnsValidation() throws DcvException {
        when(acmeValidationHandler.validate(any(AcmeValidationRequest.class))).thenThrow(new AcmeValidationException(DcvError.RANDOM_VALUE_NOT_FOUND, acmeValidationRequest));

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidator.validate(acmeValidationRequest));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
        verify(acmeValidationHandler, times(1)).validate(any(AcmeValidationRequest.class));
    }

    static Stream<Arguments> provideInvalidAcmeValidationResponse() {
        return Stream.of(
                Arguments.of(null, "1234abcd", DcvMethod.BR_3_2_2_4_7, Instant.now(), "acme-thumbprint", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", null, DcvMethod.BR_3_2_2_4_7, Instant.now(), "acme-thumbprint", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", DcvMethod.BR_3_2_2_4_7, Instant.now(), "acme-thumbprint", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", null, Instant.now(), "acme-thumbprint", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", DcvMethod.BR_3_2_2_4_7, (null), "acme-thumbprint", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", DcvMethod.BR_3_2_2_4_7, (null), null, AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", DcvMethod.BR_3_2_2_4_7, (null), "", AcmeType.ACME_DNS_01),
                Arguments.of("example.com", "1234abcd", DcvMethod.BR_3_2_2_4_7, (null), "acme-thumbprint", null)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidAcmeValidationResponse")
    void testAcmeValidator_validate_InvalidAcmeValidationResponse(String domain,
                                                                  String randomValue,
                                                                  DcvMethod dcvMethod,
                                                                  Instant prepareTime,
                                                                  String acmeThumbprint,
                                                                  AcmeType acmeType) {
        ValidationState invalidValidationState = new ValidationState(domain, prepareTime, dcvMethod);
        AcmeValidationRequest invalidAcmeValidationRequest = AcmeValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .acmeThumbprint(acmeThumbprint)
                .acmeType(acmeType)
                .validationState(invalidValidationState)
                .build();

        assertThrows(InputException.class, () -> acmeValidator.validate(invalidAcmeValidationRequest));
    }

    @Test
    void testAcmeValidator_validate_ExpiredValidationState() {
        ValidationState expiredValidationState = new ValidationState(domain, Instant.now().minus(Duration.ofDays(31)), DcvMethod.UNKNOWN);
        AcmeValidationRequest expiredAcmeValidationRequest = AcmeValidationRequest.builder()
                .domain(domain)
                .randomValue(randomValue)
                .acmeThumbprint("acme-thumbprint")
                .acmeType(AcmeType.ACME_HTTP_01)
                .validationState(expiredValidationState)
                .build();

        assertThrows(ValidationException.class, () -> acmeValidator.validate(expiredAcmeValidationRequest));
    }

    @Test
    void testAcmeValidator_prepare_HappyPath() throws DcvException {
        AcmePreparation acmePreparation = new AcmePreparation(domain);

        AcmePreparationResponse acmePreparationResponse = acmeValidator.prepare(acmePreparation);
        validationState = acmePreparationResponse.getValidationState();

        assertEquals(domain, acmePreparationResponse.getDomain());
        assertNotNull(acmePreparationResponse.getRandomValue());

        assertEquals(domain, validationState.domain());
        assertNotNull(validationState.prepareTime());
        assertEquals(DcvMethod.UNKNOWN, validationState.dcvMethod());
    }

    @Test
    void testAcmeValidator_prepare_InvalidDnsPreparation() {
        AcmePreparation acmePreparation = new AcmePreparation("");

        DcvException exception = assertThrows(DcvException.class, () ->
                acmeValidator.prepare(acmePreparation));

        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED), "expected: " + DcvError.DOMAIN_REQUIRED + " but got: " + exception.getErrors());
    }

    private static MpicDetails getMpicDetails() {
        return new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-agent-id", true), null);
    }
}