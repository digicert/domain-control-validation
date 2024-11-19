package com.digicert.validation.methods.file;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRequestTokenData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.file.prepare.FilePreparationRequest;
import com.digicert.validation.methods.file.validate.FileValidationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.file.prepare.FilePreparationResponse;
import com.digicert.validation.methods.file.validate.FileValidationHandler;
import com.digicert.validation.methods.file.validate.FileValidationResponse;
import com.digicert.validation.enums.ChallengeType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
        assertEquals("v2.1.1", DomainValidationEvidence.BR_VERSION);
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
