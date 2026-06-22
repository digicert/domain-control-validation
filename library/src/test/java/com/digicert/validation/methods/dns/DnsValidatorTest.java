package com.digicert.validation.methods.dns;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRequestTokenData;
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
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.methods.dns.validate.PersistentTxtResponse;
import com.digicert.validation.methods.dns.validate.handlers.PersistentValueHandler;
import com.digicert.validation.methods.dns.validate.handlers.RandomValueHandler;
import com.digicert.validation.methods.dns.validate.handlers.RequestTokenHandler;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.DnssecError;
import com.digicert.validation.mpic.api.dns.DnssecStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DnsValidatorTest {

    @Mock
    private RandomValueHandler randomValueHandler;

    @Mock
    private RequestTokenHandler requestTokenHandler;

    @Mock
    private PersistentValueHandler persistentValueHandler;

    private DnsValidator dnsValidator;
    private String domain;
    private String randomValue;

    @BeforeEach
    void setUp() {
        domain = "example.com";
        randomValue = "some-really-long-random-value";

        DcvContext dcvContext = spy(new DcvContext());
        doAnswer(invocation -> {
            Class<?> classType = invocation.getArgument(0);
            if (classType == RandomValueHandler.class) {
                return randomValueHandler;
            }
            if (classType == RequestTokenHandler.class) {
                return requestTokenHandler;
            }
            if (classType == PersistentValueHandler.class) {
                return persistentValueHandler;
            }
            return invocation.callRealMethod();
        }).when(dcvContext).get(any());
        dnsValidator = new DnsValidator(dcvContext);
    }

    @ParameterizedTest
    @MethodSource("challengeTypes")
    void validate_dispatchesToExpectedHandler(ChallengeType challengeType) throws DcvException {
        DnsValidationRequest request = validRequest(challengeType);
        DnsValidationResponse response = new DnsValidationResponse(true,
                getMpicDetails(),
                domain,
                domain,
                request.getDnsType(),
                challengeType == ChallengeType.RANDOM_VALUE ? randomValue : null,
                challengeType == ChallengeType.REQUEST_TOKEN ? "request-token" : null,
                null,
                Set.of());

        stubHandler(challengeType, response);

        DomainValidationEvidence evidence = dnsValidator.validate(request);

        assertNotNull(evidence);
        verifyDispatchedOnlyTo(challengeType, request);
    }

    static Stream<Arguments> provideSuccessfulValidateResponseScenarios() {
        return Stream.of(
                Arguments.of(ChallengeType.RANDOM_VALUE, "some-really-long-random-value", null, null),
                Arguments.of(ChallengeType.REQUEST_TOKEN, null, "request-token", null),
                Arguments.of(ChallengeType.PERSISTENT_VALUE, null, null, PersistentTxtResponse.builder().accountUri("http://account.uri").persistUntil(null).parsedTxtRecord(Map.of("key", Collections.singletonList("value"))).build())
        );
    }

    @ParameterizedTest
    @MethodSource("provideSuccessfulValidateResponseScenarios")
    void testDnsValidator_validate_successResponseHandling(ChallengeType challengeType,
                                                           String validRandomValue,
                                                           String validRequestToken,
                                                           PersistentTxtResponse persistentTxtResponse) throws DcvException {
        DnsValidationRequest request = validRequest(challengeType);
        DnsValidationResponse response = new DnsValidationResponse(true,
                getMpicDetails(),
                domain,
                domain,
                request.getDnsType(),
                validRandomValue,
                validRequestToken,
                persistentTxtResponse,
                Set.of());

        stubHandler(challengeType, response);

        DomainValidationEvidence evidence = dnsValidator.validate(request);

        assertNotNull(evidence);
        assertEquals(domain, evidence.getDomain());
        assertEquals(request.getDnsType(), evidence.getDnsType());
        assertEquals(request.getValidationState().dcvMethod(), evidence.getDcvMethod());
        assertEquals(validRandomValue, evidence.getRandomValue());
        assertEquals(validRequestToken, evidence.getRequestToken());
        assertEquals(domain, evidence.getDnsRecordName());
        assertNotNull(evidence.getValidationDate());
        assertEquals(persistentTxtResponse, evidence.getPersistentTxtResponse());
        verifyDispatchedOnlyTo(challengeType, request);
    }

    static Stream<Arguments> provideFailedValidateResponseScenarios() {
        DnssecDetails dnssecFailure = new DnssecDetails(DnssecStatus.INSECURE,
                DnssecError.DNSKEY_MISSING,
                null,
                "no SEP matching the DS found");
        return Stream.of(
                Arguments.of(Set.of(DcvError.INVALID_DNS_TYPE), DnssecDetails.notChecked(), null),
                Arguments.of(Set.of(DcvError.DNS_LOOKUP_DNSSEC_FAILURE), dnssecFailure, dnssecFailure)
        );
    }

    @ParameterizedTest
    @MethodSource("provideFailedValidateResponseScenarios")
    void testDnsValidator_validate_failedResponseHandling(Set<DcvError> errors,
                                                          DnssecDetails responseDnssecDetails,
                                                          DnssecDetails expectedExceptionDnssecDetails) throws DcvException {
        DnsValidationRequest request = validRequest(ChallengeType.RANDOM_VALUE);
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                responseDnssecDetails,
                Map.of("secondary-agent-id", true),
                null);
        DnsValidationResponse response = new DnsValidationResponse(false,
                mpicDetails,
                domain,
                domain,
                DnsType.TXT,
                randomValue,
                null,
                null,
                errors);

        when(randomValueHandler.validate(any(DnsValidationRequest.class))).thenReturn(response);

        ValidationException exception = assertThrows(ValidationException.class, () -> dnsValidator.validate(request));
        assertEquals(errors, exception.getErrors());
        assertEquals(expectedExceptionDnssecDetails, exception.getDnssecDetails());

        verifyDispatchedOnlyTo(ChallengeType.RANDOM_VALUE, request);
    }

    static Stream<Arguments> provideInvalidDnsValidationRequests() {
        ValidationState state = new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_7);
        return Stream.of(
                Arguments.of(DnsValidationRequest.builder().domain(null).dnsType(DnsType.TXT).challengeType(ChallengeType.RANDOM_VALUE).randomValue("some-really-long-random-value").validationState(state).build(), DcvError.DOMAIN_REQUIRED),
                Arguments.of(DnsValidationRequest.builder().domain("example.com").dnsType(null).challengeType(ChallengeType.RANDOM_VALUE).randomValue("some-really-long-random-value").validationState(state).build(), DcvError.DNS_TYPE_REQUIRED),
                Arguments.of(DnsValidationRequest.builder().domain("example.com").dnsType(DnsType.A).challengeType(ChallengeType.RANDOM_VALUE).randomValue("some-really-long-random-value").validationState(state).build(), DcvError.INVALID_DNS_TYPE),
                Arguments.of(DnsValidationRequest.builder().domain("example.com").dnsType(DnsType.TXT).challengeType(null).randomValue("some-really-long-random-value").validationState(state).build(), DcvError.CHALLENGE_TYPE_REQUIRED),
                Arguments.of(DnsValidationRequest.builder().domain("example.com").dnsType(DnsType.TXT).challengeType(ChallengeType.RANDOM_VALUE).randomValue("some-really-long-random-value").domainLabel("dnsauth.").validationState(state).build(), DcvError.DNS_DOMAIN_LABEL_INVALID),
                Arguments.of(DnsValidationRequest.builder().domain("example.com").dnsType(DnsType.TXT).challengeType(ChallengeType.RANDOM_VALUE).randomValue("some-really-long-random-value").domainLabel("_invalid.dot").validationState(state).build(), DcvError.DNS_DOMAIN_LABEL_INVALID)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidDnsValidationRequests")
    void testDnsValidator_validate_InvalidDnsValidationRequest(DnsValidationRequest request, DcvError expectedError) {
        InputException exception = assertThrows(InputException.class, () -> dnsValidator.validate(request));
        assertTrue(exception.getErrors().contains(expectedError));
        verifyNoInteractions(randomValueHandler, requestTokenHandler, persistentValueHandler);
    }

    static Stream<Arguments> provideRandomValueDnsPreparation() {
        return Stream.of(
                Arguments.of(ChallengeType.RANDOM_VALUE, DcvMethod.BR_3_2_2_4_7)
        );
    }

    @ParameterizedTest
    @MethodSource("provideRandomValueDnsPreparation")
    void testDnsValidator_prepare_HappyPath_randomValue(ChallengeType challengeType,
                                                        DcvMethod expectedMethod) throws DcvException {
        DnsPreparation dnsPreparation = new DnsPreparation(domain, DnsType.TXT, challengeType);

        DnsPreparationResponse response = dnsValidator.prepare(dnsPreparation);

        assertEquals(domain, response.getDomain());
        assertTrue(response.getAllowedFqdns().contains(domain));
        assertEquals(DnsType.TXT, response.getDnsType());
        assertEquals(expectedMethod, response.getValidationState().dcvMethod());
        assertNotNull(response.getRandomValue());
    }

    @Test
    void testDnsValidator_prepare_HappyPath_persistentValue() throws DcvException {
        DnsPreparation dnsPreparation = new DnsPreparation(domain, DnsType.TXT, ChallengeType.PERSISTENT_VALUE);

        DnsPreparationResponse response = dnsValidator.prepare(dnsPreparation);

        assertEquals(domain, response.getDomain());
        assertTrue(response.getAllowedFqdns().contains(domain));
        assertEquals(DnsType.TXT, response.getDnsType());
        assertEquals(DcvMethod.BR_3_2_2_4_22, response.getValidationState().dcvMethod());
        assertNull(response.getRandomValue());
    }

    static Stream<Arguments> provideInvalidDnsPreparation() {
        return Stream.of(
                Arguments.of(null, DnsType.TXT, ChallengeType.RANDOM_VALUE, DcvError.DOMAIN_REQUIRED),
                Arguments.of("example.com", null, ChallengeType.RANDOM_VALUE, DcvError.DNS_TYPE_REQUIRED),
                Arguments.of("example.com", DnsType.TXT, null, DcvError.CHALLENGE_TYPE_REQUIRED),
                Arguments.of("example.com", DnsType.A, ChallengeType.RANDOM_VALUE, DcvError.INVALID_DNS_TYPE),
                Arguments.of("example.com", DnsType.CNAME, ChallengeType.PERSISTENT_VALUE, DcvError.INVALID_DNS_TYPE)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidDnsPreparation")
    void testDnsValidator_prepare_InvalidDnsPreparation(String domain,
                                                        DnsType dnsType,
                                                        ChallengeType challengeType,
                                                        DcvError expectedError) {
        DnsPreparation invalidPreparation = new DnsPreparation(domain, dnsType, challengeType);

        DcvException exception = assertThrows(DcvException.class, () -> dnsValidator.prepare(invalidPreparation));
        assertTrue(exception.getErrors().contains(expectedError));
    }

    private static Stream<Arguments> challengeTypes() {
        return Stream.of(
                Arguments.of(ChallengeType.RANDOM_VALUE),
                Arguments.of(ChallengeType.REQUEST_TOKEN),
                Arguments.of(ChallengeType.PERSISTENT_VALUE)
        );
    }

    private DnsValidationRequest validRequest(ChallengeType challengeType) {
        DcvMethod method = challengeType == ChallengeType.PERSISTENT_VALUE
                                   ? DcvMethod.BR_3_2_2_4_22
                                   : DcvMethod.BR_3_2_2_4_7;

        DnsValidationRequest.DnsValidationRequestBuilder builder = DnsValidationRequest.builder()
                .domain(domain)
                                                                           .dnsType(DnsType.TXT)
                                                                           .challengeType(challengeType)
                                                                           .validationState(new ValidationState(domain, Instant.now(), method));

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            builder.randomValue(randomValue);
        }
        if (challengeType == ChallengeType.REQUEST_TOKEN) {
            builder.requestTokenData(new BasicRequestTokenData("hashing-key", "hashing-value"));
        }
        if (challengeType == ChallengeType.PERSISTENT_VALUE) {
            builder.accountUri("https://authority.example/acct/123");
        }
        return builder.build();
    }

    private void stubHandler(ChallengeType challengeType, DnsValidationResponse response) throws DcvException {
        switch (challengeType) {
            case RANDOM_VALUE ->
                    when(randomValueHandler.validate(any(DnsValidationRequest.class))).thenReturn(response);
            case REQUEST_TOKEN ->
                    when(requestTokenHandler.validate(any(DnsValidationRequest.class))).thenReturn(response);
            case PERSISTENT_VALUE ->
                    when(persistentValueHandler.validate(any(DnsValidationRequest.class))).thenReturn(response);
        }
    }

    private void verifyDispatchedOnlyTo(ChallengeType challengeType, DnsValidationRequest request) throws DcvException {
        switch (challengeType) {
            case RANDOM_VALUE -> {
                verify(randomValueHandler).validate(request);
                verifyNoInteractions(requestTokenHandler, persistentValueHandler);
            }
            case REQUEST_TOKEN -> {
                verify(requestTokenHandler).validate(request);
                verifyNoInteractions(randomValueHandler, persistentValueHandler);
            }
            case PERSISTENT_VALUE -> {
                verify(persistentValueHandler).validate(request);
                verifyNoInteractions(randomValueHandler, requestTokenHandler);
            }
        }
    }

    private static MpicDetails getMpicDetails() {
        return new MpicDetails(true,
                "primary-agent",
                3,
                3,
                DnssecDetails.notChecked(),
                Map.of("secondary-agent-id", true),
                null);
    }

}
