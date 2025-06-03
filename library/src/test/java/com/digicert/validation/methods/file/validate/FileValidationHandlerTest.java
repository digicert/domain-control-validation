package com.digicert.validation.methods.file.validate;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicFileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FileValidationHandlerTest {

    private FileValidationHandler fileValidationHandler;
    private RandomValueValidator randomValueValidator;
    private RequestTokenValidator requestTokenValidator;
    private MpicFileService mpicFileService;

    @BeforeEach
    void setUp() {
        initializeMocks(new DcvConfiguration.DcvConfigurationBuilder().build());
    }

    private void initializeMocks(DcvConfiguration dcvConfiguration) {
        mpicFileService = mock(MpicFileService.class);
        randomValueValidator = mock(RandomValueValidator.class);
        requestTokenValidator = mock(RequestTokenValidator.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(MpicFileService.class)).thenReturn(mpicFileService);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(randomValueValidator);
        when(dcvContext.get(RequestTokenValidator.class)).thenReturn(requestTokenValidator);
        when(dcvContext.getDcvConfiguration()).thenReturn(dcvConfiguration);

        fileValidationHandler = new FileValidationHandler(dcvContext);
    }

    @Test
    void testGetFileUrls_noHttps() {
        // Arrange
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder().fileValidationCheckHttps(false).build();
        initializeMocks(dcvConfiguration);
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequest();
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls(fileValidationRequestBuilder.build());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(1, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_usingHttps() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequest();
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls(fileValidationRequestBuilder.build());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(2, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("https://example.com/.well-known/pki-validation/fileauth.txt")));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_CustomFilename() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequest();
        fileValidationRequestBuilder.filename("customFilename.txt");
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls(fileValidationRequestBuilder.build());

        // Assert
        assertNotNull(fileUrls);
        assertEquals(2, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/customFilename.txt")));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("https://example.com/.well-known/pki-validation/customFilename.txt")));
    }

    @Test
    void testValidate_validResponse() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequest();
        when(mpicFileService.getMpicFileDetails(anyList())).thenReturn(getMpicFileDetails(true, null, 200, "randomValue"));
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("randomValue"), null);
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

        FileValidationResponse response = fileValidationHandler.validate(fileValidationRequestBuilder.build());
        // Assert
        assertNotNull(response);
        assertTrue(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals("randomValue", response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_InvalidResponse_ExceptionFromClient() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequest();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, DcvError.FILE_VALIDATION_CLIENT_ERROR, 200, "randomValue");
        when(mpicFileService.getMpicFileDetails(anyList())).thenReturn(mpicFileDetails);

        FileValidationResponse response = fileValidationHandler.validate(fileValidationRequestBuilder.build());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_VALIDATION_CLIENT_ERROR));
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_InvalidResponse_InvalidStatusCode() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest().build();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, DcvError.FILE_VALIDATION_INVALID_STATUS_CODE, 400, "randomValue");
        when(mpicFileService.getMpicFileDetails(anyList())).thenReturn(mpicFileDetails);

        // Act
        FileValidationResponse response = fileValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_VALIDATION_INVALID_STATUS_CODE));
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_InvalidResponse_EmptyFileContent() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest().build();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, "");
        when(mpicFileService.getMpicFileDetails(anyList())).thenReturn(mpicFileDetails);

        // Act
        FileValidationResponse response = fileValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.FILE_VALIDATION_EMPTY_RESPONSE));
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_TokenValidatorErrors() {
        // Arrange
        FileValidationRequest request = getRandomValueFileValidationRequest().build();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, "file content");
        when(mpicFileService.getMpicFileDetails(anyList())).thenReturn(mpicFileDetails);

        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.REQUEST_TOKEN_EMPTY_TEXT_BODY));
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

        // Act
        FileValidationResponse response = fileValidationHandler.validate(request);

        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.REQUEST_TOKEN_EMPTY_TEXT_BODY));
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    private FileValidationRequest.FileValidationRequestBuilder getRandomValueFileValidationRequest() {
        return FileValidationRequest.builder()
            .domain("example.com")
            .randomValue("randomValue").challengeType(ChallengeType.RANDOM_VALUE)
            .challengeType(ChallengeType.RANDOM_VALUE);
    }

    private FileValidationRequest getTokenFileValidationRequest() {
        return FileValidationRequest.builder()
                .domain("example.com")
                .randomValue("randomValue")
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();
    }

    private static MpicFileDetails getMpicFileDetails(boolean corroborated, DcvError dcvError, int statusCode, String fileContents) {
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated));

        return new MpicFileDetails(mpicDetails,
                "http://example.com/.well-known/pki-validation/fileauth.txt",
                fileContents,
                statusCode,
                dcvError);
    }
}