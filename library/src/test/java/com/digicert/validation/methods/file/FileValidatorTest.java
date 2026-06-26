package com.digicert.validation.methods.file;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRequestTokenData;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.file.prepare.FilePreparationRequest;
import com.digicert.validation.methods.file.prepare.FilePreparationResponse;
import com.digicert.validation.methods.file.validate.FileValidationHandler;
import com.digicert.validation.methods.file.validate.FileValidationRequest;
import com.digicert.validation.methods.file.validate.FileValidationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FileValidatorTest {

    private final String defaultRandomValue = "some-really-long-random-value";
    private FileValidator fileValidator;
    private FileValidationHandler fileValidationHandler;

    @BeforeEach
    public void setUp() {
        fileValidationHandler = mock(FileValidationHandler.class);

        DcvContext dcvContext = spy(new DcvContext());
        doCallRealMethod().when(dcvContext).get(any());
        doReturn(fileValidationHandler).when(dcvContext).get(FileValidationHandler.class);

        fileValidator = new FileValidator(dcvContext);
    }

    @Test
    void testVerifyFileValidationRequest_ValidRequest() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder request = getRandomValueFileValidationRequest();

        // Act & Assert
        assertDoesNotThrow(() -> fileValidator.verifyFileValidationRequest(request.build()));
    }

    @Test
    void testVerifyFileValidationRequest_ipv4_withBR_3_2_2_5_1_shouldSucceed() {
        // Arrange
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("1.2.3.4")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("1.2.3.4", Instant.now(), DcvMethod.BR_3_2_2_5_1))
                .build();
        // Act & Assert
        assertDoesNotThrow(() -> fileValidator.verifyFileValidationRequest(request));
    }

    @Test
    void testVerifyFileValidationRequest_ipv6_withBR_3_2_2_5_1_shouldSucceed() {
        // Arrange — use a genuinely public IPv6 address (ARIN allocation); 2001:db8:: is documentation-only and is rejected
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("2600::1")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("2600::1", Instant.now(), DcvMethod.BR_3_2_2_5_1))
                .build();
        // Act & Assert
        assertDoesNotThrow(() -> fileValidator.verifyFileValidationRequest(request));
    }

    @Test
    void testVerifyFileValidationRequest_ipv4_withBR_3_2_2_4_18_shouldThrowInvalidDcvMethod() {
        // Arrange — IP address subject but wrong DCV method (domain method)
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("1.2.3.4")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("1.2.3.4", Instant.now(), DcvMethod.BR_3_2_2_4_18))
                .build();
        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_DCV_METHOD));
    }

    @Test
    void testVerifyFileValidationRequest_domain_withBR_3_2_2_5_1_shouldThrowInvalidDcvMethod() {
        // Arrange — domain subject but wrong DCV method (IP method)
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("example.com")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_5_1))
                .build();
        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.INVALID_DCV_METHOD));
    }

    @Test
    void testVerifyFileValidationRequest_InvalidDomain() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest()
            .domain("")
            .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void testVerifyFileValidationRequest_NullRandomValue() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest()
                .randomValue(null)
                .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_REQUIRED));
    }

    @Test
    void testVerifyFileValidationRequest_NullDomain() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest()
            .domain(null)
            .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void testVerifyFileValidationRequest_EmptyRandomValue() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest()
                .randomValue("")
                .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_REQUIRED));
    }

    @Test
    void fileValidationPreparationResponseShouldContainRandomValue() throws DcvException {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com");
        FilePreparationResponse response = fileValidator.prepare(filePreparationRequest);
        assertNotNull(response.getRandomValue());
    }

    @Test
    void fileValidationPreparationResponseShouldContainDomain() throws DcvException {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com");
        FilePreparationResponse response = fileValidator.prepare(filePreparationRequest);
        assertEquals("example.com", response.getDomain());
    }

    @Test
    void prepare_withIpv4Address_shouldUseBR_3_2_2_5_1Method() throws DcvException {
        FilePreparationRequest request = new FilePreparationRequest("1.2.3.4");
        FilePreparationResponse response = fileValidator.prepare(request);
        assertEquals(DcvMethod.BR_3_2_2_5_1, response.getValidationState().dcvMethod());
    }

    @Test
    void prepare_withIpv6Address_shouldUseBR_3_2_2_5_1Method() throws DcvException {
        // Use a genuinely public IPv6 address (ARIN allocation); 2001:db8:: is documentation-only and is rejected
        FilePreparationRequest request = new FilePreparationRequest("2600::1");
        FilePreparationResponse response = fileValidator.prepare(request);
        assertEquals(DcvMethod.BR_3_2_2_5_1, response.getValidationState().dcvMethod());
    }

    @Test
    void prepare_withDomainName_shouldUseBR_3_2_2_4_18Method() throws DcvException {
        FilePreparationRequest request = new FilePreparationRequest("example.com");
        FilePreparationResponse response = fileValidator.prepare(request);
        assertEquals(DcvMethod.BR_3_2_2_4_18, response.getValidationState().dcvMethod());
    }

    @Test
    void prepare_withPrivateIpv4_shouldThrowIpAddressReserved() {
        FilePreparationRequest request = new FilePreparationRequest("192.168.1.1");
        InputException exception = assertThrows(InputException.class, () -> fileValidator.prepare(request));
        assertTrue(exception.getErrors().contains(DcvError.IP_ADDRESS_RESERVED));
    }

    @Test
    void prepare_withPrivateIpv6_shouldThrowIpAddressReserved() {
        // fe80::/10 is link-local — not a Global Unicast address
        FilePreparationRequest request = new FilePreparationRequest("fe80::1");
        InputException exception = assertThrows(InputException.class, () -> fileValidator.prepare(request));
        assertTrue(exception.getErrors().contains(DcvError.IP_ADDRESS_RESERVED));
    }

    @Test
    void fileValidationPreparationShouldThrowValidationExceptionForNullDomain() {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest(null);
        InputException exception = assertThrows(InputException.class, () -> fileValidator.prepare(filePreparationRequest));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void fileValidationPreparationResponseShouldContainValidationState() throws DcvException {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com");
        FilePreparationResponse response = fileValidator.prepare(filePreparationRequest);
        assertNotNull(response.getValidationState());
    }

    @Test
    void fileValidationPreparationResponseCustomFilename() throws DcvException {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com", "customfilename.txt", ChallengeType.RANDOM_VALUE);
        FilePreparationResponse response = fileValidator.prepare(filePreparationRequest);
        String fileLocation = fileValidator.getFileUrl(filePreparationRequest.domain(), filePreparationRequest.filename());
        assertEquals(fileLocation, response.getFileLocation());
    }

    @Test
    void fileValidationPreparationResponse_InvalidCustomFilename() {
        FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com", "invalid*filename.txt", ChallengeType.RANDOM_VALUE);
        assertThrows(IllegalArgumentException.class, () -> fileValidator.prepare(filePreparationRequest));
    }

    @Test
    void verifyFileValidationRequest_randomValueInFilename_shouldThrowChallengeValueInRequestNotAllowed() {
        // The random value must not appear in the GET request URL (BR requirement).
        // Embedding it in the filename would expose it on the wire pre-fetch.
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("example.com")
                .randomValue(defaultRandomValue)
                .filename(defaultRandomValue + ".txt")   // random value embedded in filename
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18))
                .build();
        InputException exception = assertThrows(InputException.class,
                () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.CHALLENGE_VALUE_IN_REQUEST_NOT_ALLOWED));
    }

    @Test
    void verifyFileValidationRequest_invalidFilenameFormat_shouldThrowIllegalArgumentException() {
        // Filename validation must also run in the validate path, not only in prepare.
        FileValidationRequest request = FileValidationRequest.builder()
                .domain("example.com")
                .randomValue(defaultRandomValue)
                .filename("invalid*filename.txt")   // '*' is not an allowed filename character
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18))
                .build();
        assertThrows(IllegalArgumentException.class,
                () -> fileValidator.verifyFileValidationRequest(request));
    }

    @Test
    void validateShouldReturnDomainValidationEvidence() throws DcvException {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest().build();
        FileValidationResponse response = getDefaultFileValidationResponse().build();
        when(fileValidationHandler.validate(request)).thenReturn(response);

        // Act
        DomainValidationEvidence evidence = fileValidator.validate(request);

        // Assert
        assertNotNull(evidence);
        assertEquals("example.com", evidence.getDomain());
        assertEquals("v2.2.6", DomainValidationEvidence.BR_VERSION);
        assertNotNull(evidence.getValidationDate());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", evidence.getFileUrl());
        assertEquals("randomValue", evidence.getRandomValue());
        assertNull(evidence.getRequestToken());
        assertEquals(DcvMethod.BR_3_2_2_4_18, evidence.getDcvMethod());
    }

    @Test
    void validateShouldNotReturnDomainValidationEvidence() {
        // Arrange
        FileValidationRequest request = getTokenFileValidationRequest().build();
        FileValidationResponse response = getDefaultFileValidationResponse()
                .isValid(false)
                .errors(Set.of(DcvError.FILE_VALIDATION_CLIENT_ERROR))
                .build();

        when(fileValidationHandler.validate(request)).thenReturn(response);

        // Act
        ValidationException exception = assertThrows(ValidationException.class, () -> fileValidator.validate(request));

        // Assert
        assertTrue(exception.getErrors().contains(DcvError.FILE_VALIDATION_CLIENT_ERROR));
    }

    @Test
    void testValidateFileValidationRequest_NullRequestTokenData() {
        // Arrange
        FileValidationRequest request = getTokenFileValidationRequest()
                .requestTokenData(null)
                .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileValidator.verifyFileValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.REQUEST_TOKEN_DATA_REQUIRED));
    }

    private FileValidationResponse.FileValidationResponseBuilder getDefaultFileValidationResponse() {
        return FileValidationResponse.builder()
                .isValid(true)
                .domain("example.com")
                .fileUrl("http://example.com/.well-known/pki-validation/fileauth.txt")
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validRandomValue("randomValue")
                .validRequestToken(null);
    }


    private FileValidationRequest.FileValidationRequestBuilder getRandomValueFileValidationRequest() {
        return FileValidationRequest.builder()
                .domain("example.com")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18));
    }

    private FileValidationRequest.FileValidationRequestBuilder getTokenFileValidationRequest() {
        return FileValidationRequest.builder()
                .domain("example.com")
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .requestTokenData(new BasicRequestTokenData("someHashingKey", "someHashingValue"))
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18));
    }
}
