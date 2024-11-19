package com.digicert.validation.methods.fileauth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.Set;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationRequest;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationResponse;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationHandler;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationRequest;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationResponse;
import com.digicert.validation.enums.ChallengeType;

class FileAuthValidatorTest {

    private final String defaultRandomValue = "some-really-long-random-value";
    private FileAuthValidator fileAuthValidator;
    private FileAuthValidationHandler fileAuthValidationHandler;

    @BeforeEach
    public void setUp() {
        fileAuthValidationHandler = mock(FileAuthValidationHandler.class);

        DcvContext dcvContext = spy(new DcvContext());
        doCallRealMethod().when(dcvContext).get(any());
        doReturn(fileAuthValidationHandler).when(dcvContext).get(FileAuthValidationHandler.class);

        fileAuthValidator = new FileAuthValidator(dcvContext);
    }

    @Test
    void testVerifyFileAuthValidationRequest_ValidRequest() {
        // Arrange
        FileAuthValidationRequest.FileAuthValidationRequestBuilder request = getRandomValueFileAuthValidationRequest();

        // Act & Assert
        assertDoesNotThrow(() -> fileAuthValidator.verifyFileAuthValidationRequest(request.build()));
    }

    @Test
    void testVerifyFileAuthValidationRequest_InvalidDomain() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest()
            .domain("")
            .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void testVerifyFileAuthValidationRequest_NullRandomValue() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest()
                .randomValue(null)
                .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_REQUIRED));
    }

    @Test
    void testVerifyFileAuthValidationRequest_NullDomain() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest()
            .domain(null)
            .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void testVerifyFileAuthValidationRequest_EmptyRandomValue() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest()
                .randomValue("")
                .build();

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_REQUIRED));
    }

    @Test
    void fileAuthPreparationResponseShouldContainRandomValue() throws DcvException {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest("example.com");
        FileAuthPreparationResponse response = fileAuthValidator.prepare(fileAuthPreparationRequest);
        assertNotNull(response.getRandomValue());
    }

    @Test
    void fileAuthPreparationResponseShouldContainDomain() throws DcvException {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest("example.com");
        FileAuthPreparationResponse response = fileAuthValidator.prepare(fileAuthPreparationRequest);
        assertEquals("example.com", response.getDomain());
    }

    @Test
    void fileAuthPreparationShouldThrowValidationExceptionForNullDomain() {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest(null);
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.prepare(fileAuthPreparationRequest));
        assertTrue(exception.getErrors().contains(DcvError.DOMAIN_REQUIRED));
    }

    @Test
    void fileAuthPreparationResponseShouldContainValidationState() throws DcvException {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest("example.com");
        FileAuthPreparationResponse response = fileAuthValidator.prepare(fileAuthPreparationRequest);
        assertNotNull(response.getValidationState());
    }

    @Test
    void fileAuthPreparationResponseCustomFilename() throws DcvException {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest("example.com", "customfilename.txt", ChallengeType.RANDOM_VALUE);
        FileAuthPreparationResponse response = fileAuthValidator.prepare(fileAuthPreparationRequest);
        String fileLocation = fileAuthValidator.getFileUrl(fileAuthPreparationRequest.domain(), fileAuthPreparationRequest.filename());
        assertEquals(fileLocation, response.getFileLocation());
    }

    @Test
    void fileAuthPreparationResponse_InvalidCustomFilename() {
        FileAuthPreparationRequest fileAuthPreparationRequest = new FileAuthPreparationRequest("example.com", "invalid*filename.txt", ChallengeType.RANDOM_VALUE);
        assertThrows(IllegalArgumentException.class, () -> fileAuthValidator.prepare(fileAuthPreparationRequest));
    }

    @Test
    void validateShouldReturnDomainValidationEvidence() throws DcvException {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest().build();
        FileAuthValidationResponse response = getDefaultFileAuthValidationResponse().build();
        when(fileAuthValidationHandler.validate(request)).thenReturn(response);

        // Act
        DomainValidationEvidence evidence = fileAuthValidator.validate(request);

        // Assert
        assertNotNull(evidence);
        assertEquals("example.com", evidence.getDomain());
        assertEquals("v2.0.7", DomainValidationEvidence.BR_VERSION);
        assertNotNull(evidence.getValidationDate());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", evidence.getFileUrl());
        assertEquals("randomValue", evidence.getRandomValue());
        assertNull(evidence.getFoundToken());
        assertEquals(DcvMethod.BR_3_2_2_4_18, evidence.getDcvMethod());
    }

    @Test
    void validateShouldNotReturnDomainValidationEvidence() {
        // Arrange
        FileAuthValidationRequest request = getTokenFileAuthValidationRequest().build();
        FileAuthValidationResponse response = getDefaultFileAuthValidationResponse()
                .isValid(false)
                .errors(Set.of(DcvError.FILE_AUTH_CLIENT_ERROR))
                .build();

        when(fileAuthValidationHandler.validate(request)).thenReturn(response);

        // Act
        ValidationException exception = assertThrows(ValidationException.class, () -> fileAuthValidator.validate(request));

        // Assert
        assertTrue(exception.getErrors().contains(DcvError.FILE_AUTH_CLIENT_ERROR));
    }

    @Test
    void testValidateFileAuthValidationRequest_NullTokenKey() {
        // Arrange
        FileAuthValidationRequest request = getTokenFileAuthValidationRequest()
                .tokenKey(null)
                .build();
        FileAuthValidationResponse response = getDefaultFileAuthValidationResponse().build();
        when(fileAuthValidationHandler.validate(request)).thenReturn(response);

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));
        assertTrue(exception.getErrors().contains(DcvError.TOKEN_KEY_REQUIRED));
    }

    @Test
    void testValidateFileAuthValidationRequest_NullTokenValue() {
        // Arrange
        FileAuthValidationRequest request = getTokenFileAuthValidationRequest()
                .tokenValue(null)
                .build();
        FileAuthValidationResponse response = getDefaultFileAuthValidationResponse().build();
        when(fileAuthValidationHandler.validate(request)).thenReturn(response);

        // Act & Assert
        InputException exception = assertThrows(InputException.class, () -> fileAuthValidator.verifyFileAuthValidationRequest(request));

        assertTrue(exception.getErrors().contains(DcvError.TOKEN_VALUE_REQUIRED));
    }

    private FileAuthValidationResponse.FileAuthValidationResponseBuilder getDefaultFileAuthValidationResponse() {
        return FileAuthValidationResponse.builder()
                .isValid(true)
                .domain("example.com")
                .fileUrl("http://example.com/.well-known/pki-validation/fileauth.txt")
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validRandomValue("randomValue")
                .validToken(null);
    }


    private FileAuthValidationRequest.FileAuthValidationRequestBuilder getRandomValueFileAuthValidationRequest() {
        return FileAuthValidationRequest.builder()
                .domain("example.com")
                .randomValue(defaultRandomValue)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18));
    }

    private FileAuthValidationRequest.FileAuthValidationRequestBuilder getTokenFileAuthValidationRequest() {
        return FileAuthValidationRequest.builder()
                .domain("example.com")
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .tokenKey("someTokenKey")
                .tokenValue("someTokenValue")
                .validationState(new ValidationState("example.com", Instant.now(), DcvMethod.BR_3_2_2_4_18));
    }
}
