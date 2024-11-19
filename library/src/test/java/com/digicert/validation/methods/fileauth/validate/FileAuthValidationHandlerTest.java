package com.digicert.validation.methods.fileauth.validate;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.client.fileauth.FileAuthClient;
import com.digicert.validation.client.fileauth.FileAuthClientResponse;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.secrets.RandomValueValidator;
import com.digicert.validation.secrets.TokenValidator;
import com.digicert.validation.secrets.ChallengeValidationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FileAuthValidationHandlerTest {

    private FileAuthValidationHandler fileAuthValidationHandler;
    private FileAuthClient fileAuthClient;
    private RandomValueValidator randomValueValidator;
    private TokenValidator tokenValidator;

    @BeforeEach
    void setUp() {
        initializeMocks(new DcvConfiguration.DcvConfigurationBuilder().build());
    }

    private void initializeMocks(DcvConfiguration dcvConfiguration) {
        fileAuthClient = mock(FileAuthClient.class);
        randomValueValidator = mock(RandomValueValidator.class);
        tokenValidator = mock(TokenValidator.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(FileAuthClient.class)).thenReturn(fileAuthClient);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(randomValueValidator);
        when(dcvContext.get(TokenValidator.class)).thenReturn(tokenValidator);
        when(dcvContext.getDcvConfiguration()).thenReturn(dcvConfiguration);

        fileAuthValidationHandler = new FileAuthValidationHandler(dcvContext);
    }

    @Test
    void testGetFileUrls_noHttps() {
        // Arrange
        FileAuthValidationRequest.FileAuthValidationRequestBuilder fileAuthValidationRequestBuilder = getRandomValueFileAuthValidationRequest();
        // Act
        List<String> fileUrls = fileAuthValidationHandler.getFileUrls(fileAuthValidationRequestBuilder.build());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(1, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_usingHttps() {
        // Arrange
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder().fileAuthCheckHttps(true).build();
        initializeMocks(dcvConfiguration);

        FileAuthValidationRequest.FileAuthValidationRequestBuilder fileAuthValidationRequestBuilder = getRandomValueFileAuthValidationRequest();
        // Act
        List<String> fileUrls = fileAuthValidationHandler.getFileUrls(fileAuthValidationRequestBuilder.build());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(2, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("https://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_CustomFilename() {
        // Arrange
        FileAuthValidationRequest.FileAuthValidationRequestBuilder fileAuthValidationRequestBuilder = getRandomValueFileAuthValidationRequest();
        fileAuthValidationRequestBuilder.filename("customFilename.txt");
        // Act
        List<String> fileUrls = fileAuthValidationHandler.getFileUrls(fileAuthValidationRequestBuilder.build());

        // Assert
        assertNotNull(fileUrls);
        assertEquals(1, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/customFilename.txt")));
    }

    @Test
    void testValidate_ValidResponse() {
        // Arrange
        FileAuthValidationRequest.FileAuthValidationRequestBuilder fileAuthValidationRequestBuilder = getRandomValueFileAuthValidationRequest();
        when(fileAuthClient.executeRequest(anyString())).thenReturn(new FileAuthClientResponse("http://example.com/.well-known/pki-validation/fileauth.txt", "randomValue", 200));
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("randomValue"), null);
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

        FileAuthValidationResponse response = fileAuthValidationHandler.validate(fileAuthValidationRequestBuilder.build());
        // Assert
        assertNotNull(response);
        assertTrue(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals("randomValue", response.validRandomValue());
        assertNull(response.validToken());
    }

    @Test
    void testValidate_InvalidResponse_ExceptionFromClient() {
        // Arrange
        FileAuthValidationRequest.FileAuthValidationRequestBuilder fileAuthValidationRequestBuilder = getRandomValueFileAuthValidationRequest();
        when(fileAuthClient.executeRequest(anyString())).thenReturn(
                new FileAuthClientResponse(
                        "http://example.com/.well-known/pki-validation/fileauth.txt",
                        null,
                        200,
                        new IOException("Intentional Exception"),
                        DcvError.FILE_AUTH_CLIENT_ERROR));

        FileAuthValidationResponse response = fileAuthValidationHandler.validate(fileAuthValidationRequestBuilder.build());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_AUTH_CLIENT_ERROR));
        assertNull(response.validToken());
    }

    @Test
    void testValidate_InvalidResponse_InvalidStatusCode() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest().build();
        when(fileAuthClient.executeRequest(anyString())).thenReturn(new FileAuthClientResponse("http://example.com/.well-known/pki-validation/fileauth.txt",
                "invalidValue", 400));

        // Act
        FileAuthValidationResponse response = fileAuthValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_AUTH_INVALID_STATUS_CODE));
        assertNull(response.validRandomValue());
        assertNull(response.validToken());
    }

    @Test
    void testValidate_InvalidResponse_EmptyFileContent() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest().build();
        when(fileAuthClient.executeRequest(anyString())).thenReturn(new FileAuthClientResponse("http://example.com/.well-known/pki-validation/fileauth.txt",
                "", 200));

        // Act
        FileAuthValidationResponse response = fileAuthValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_AUTH_EMPTY_RESPONSE));
        assertNull(response.validRandomValue());
        assertNull(response.validToken());
    }


    @Test
    void testValidate_TokenValidatorErrors() {
        // Arrange
        FileAuthValidationRequest request = getRandomValueFileAuthValidationRequest().build();
        when(fileAuthClient.executeRequest(anyString())).thenReturn(new FileAuthClientResponse("http://example.com/.well-known/pki-validation/fileauth.txt",
                "file content", 200));

        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.TOKEN_ERROR_EMPTY_TXT_BODY));
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

        // Act
        FileAuthValidationResponse response = fileAuthValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.TOKEN_ERROR_EMPTY_TXT_BODY));
        assertNull(response.validRandomValue());
        assertNull(response.validToken());
    }

    private FileAuthValidationRequest.FileAuthValidationRequestBuilder getRandomValueFileAuthValidationRequest() {
        return FileAuthValidationRequest.builder()
            .domain("example.com")
            .randomValue("randomValue").challengeType(ChallengeType.RANDOM_VALUE)
            .challengeType(ChallengeType.RANDOM_VALUE);
    }

    private FileAuthValidationRequest getTokenFileAuthValidationRequest() {
        return FileAuthValidationRequest.builder()
                .domain("example.com")
                .randomValue("randomValue")
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();
    }
}