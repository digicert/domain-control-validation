package com.digicert.validation.methods.file.validate;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRequestTokenData;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicFileService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
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
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls((getRandomValueFileValidationRequest()));
        // Assert
        assertNotNull(fileUrls);
        assertEquals(1, fileUrls.size());
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_usingHttps() {
        // Arrange
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls(getRandomValueFileValidationRequest());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(2, fileUrls.size());
        assertTrue(fileUrls.get(0).startsWith("https://"));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("https://example.com/.well-known/pki-validation/fileauth.txt")));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_usingHttps_checkHttpFirst() {
        // Arrange
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder().fileValidationCheckHttpsFirst(false).build();
        initializeMocks(dcvConfiguration);
        // Act
        List<String> fileUrls = fileValidationHandler.getFileUrls(getRandomValueFileValidationRequest());
        // Assert
        assertNotNull(fileUrls);
        assertEquals(2, fileUrls.size());
        assertTrue(fileUrls.get(0).startsWith("http://"));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("https://example.com/.well-known/pki-validation/fileauth.txt")));
        assertTrue(fileUrls.stream().anyMatch(url -> url.contains("http://example.com/.well-known/pki-validation/fileauth.txt")));
    }

    @Test
    void testGetFileUrls_CustomFilename() {
        // Arrange
        FileValidationRequest.FileValidationRequestBuilder fileValidationRequestBuilder = getRandomValueFileValidationRequestBuilder();
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
        when(mpicFileService.getMpicFileDetails(anyList(), eq("randomValue"))).thenReturn(getMpicFileDetails(true, null, 200, "randomValue"));
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("randomValue"), null);
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

        FileValidationResponse response = fileValidationHandler.validate(getRandomValueFileValidationRequest());
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
    void testValidate_validResponse_requestToken() {
        // Arrange
        PrimaryFileResponse primaryFileResponse = getPrimaryFileResponse(AgentStatus.FILE_SUCCESS);
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(primaryFileResponse);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("some-token-value"), null);
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(challengeValidationResponse);
        when(mpicFileService.getMpicFileDetails(eq(primaryFileResponse.fileUrl()), eq("some-token-value")))
                .thenReturn(getMpicFileDetails(true, null, 200, "some-token-value"));

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertTrue(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertEquals("some-token-value", response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_validPrimaryResponse_missingToken_requestToken() {
        // Arrange
        PrimaryFileResponse primaryFileResponse = getPrimaryFileResponse(AgentStatus.FILE_SUCCESS);
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(primaryFileResponse);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(challengeValidationResponse);

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNull(response.mpicDetails());
    }

    @Test
    void testValidate_validPrimaryResponse_nonCorroborated_requestToken() {
        // Arrange
        PrimaryFileResponse primaryFileResponse = getPrimaryFileResponse(AgentStatus.FILE_SUCCESS);
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(primaryFileResponse);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("some-token-value"), null);
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(challengeValidationResponse);
        when(mpicFileService.getMpicFileDetails(eq(primaryFileResponse.fileUrl()), eq("some-token-value")))
                .thenReturn(getMpicFileDetails(false, DcvError.MPIC_CORROBORATION_ERROR, 200, "some-token-value"));

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_validPrimaryResponse_missingMpicResponse_requestToken() {
        // Arrange
        PrimaryFileResponse primaryFileResponse = getPrimaryFileResponse(AgentStatus.FILE_SUCCESS);
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(primaryFileResponse);
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(new ChallengeValidationResponse(Optional.of("some-token-value"), Set.of()));

        when(mpicFileService.getMpicFileDetails(eq(primaryFileResponse.fileUrl()), eq("some-token-value")))
                .thenReturn(getMpicFileDetails(true, null, 200, "some-other-token-value"));
        when(requestTokenValidator.validate(any(), eq("some-other-token-value"))).thenReturn(new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND)));

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNotNull(response.mpicDetails());
    }

    @Test
    void testValidate_invalidPrimaryResponse_requestToken() {
        // Arrange
        PrimaryFileResponse primaryFileResponse = getPrimaryFileResponse(AgentStatus.FILE_NOT_FOUND);
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(primaryFileResponse);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("some-token-value"), null);
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(challengeValidationResponse);

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertEquals("http://example.com/.well-known/pki-validation/fileauth.txt", response.fileUrl());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNull(response.mpicDetails());
    }

    @Test
    void testValidate_nullPrimaryResponse_requestToken() {
        // Arrange
        when(mpicFileService.getPrimaryOnlyFileResponse(anyList())).thenReturn(null);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.of("some-token-value"), null);
        when(requestTokenValidator.validate(any(), eq("some-token-value"))).thenReturn(challengeValidationResponse);

        FileValidationResponse response = fileValidationHandler.validate(getRequestTokenFileValidationRequest());
        // Assert
        assertNotNull(response);
        assertFalse(response.isValid());
        assertEquals("example.com", response.domain());
        assertNull(response.fileUrl());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertNull(response.mpicDetails());
    }

    @Test
    void testValidate_InvalidResponse_ExceptionFromClient() {
        // Arrange
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, DcvError.FILE_VALIDATION_CLIENT_ERROR, 200, "randomValue");
        when(mpicFileService.getMpicFileDetails(anyList(), eq("randomValue"))).thenReturn(mpicFileDetails);

        FileValidationResponse response = fileValidationHandler.validate(getRandomValueFileValidationRequest());
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
        FileValidationRequest request = getRandomValueFileValidationRequest();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, DcvError.FILE_VALIDATION_INVALID_STATUS_CODE, 400, "randomValue");
        when(mpicFileService.getMpicFileDetails(anyList(), eq("randomValue"))).thenReturn(mpicFileDetails);

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
        FileValidationRequest request = getRandomValueFileValidationRequest();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, "");
        when(mpicFileService.getMpicFileDetails(anyList(), eq("randomValue"))).thenReturn(mpicFileDetails);
        ChallengeValidationResponse challengeValidationResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.FILE_VALIDATION_EMPTY_RESPONSE));
        when(randomValueValidator.validate(anyString(), anyString())).thenReturn(challengeValidationResponse);

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
        FileValidationRequest request = getRandomValueFileValidationRequest();
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, "file content");
        when(mpicFileService.getMpicFileDetails(anyList(), eq("randomValue"))).thenReturn(mpicFileDetails);

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

    private FileValidationRequest getRandomValueFileValidationRequest() {
        return getRandomValueFileValidationRequestBuilder()
                .build();
    }


    private FileValidationRequest.FileValidationRequestBuilder getRandomValueFileValidationRequestBuilder() {
        return FileValidationRequest.builder()
                .domain("example.com")
                .randomValue("randomValue")
                .challengeType(ChallengeType.RANDOM_VALUE);
    }

    private FileValidationRequest getRequestTokenFileValidationRequest() {
        return getRequestTokenFileValidationRequestBuilder()
                .build();
    }

    private FileValidationRequest.FileValidationRequestBuilder getRequestTokenFileValidationRequestBuilder() {
        return FileValidationRequest.builder()
                .domain("example.com")
                .requestTokenData(new BasicRequestTokenData("hashing-key", "hashing-value"))
                .challengeType(ChallengeType.REQUEST_TOKEN);
    }

    private static MpicFileDetails getMpicFileDetails(boolean corroborated, DcvError dcvError, int statusCode, String fileContents) {
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated), null);

        return new MpicFileDetails(mpicDetails,
                "http://example.com/.well-known/pki-validation/fileauth.txt",
                fileContents,
                statusCode,
                dcvError);
    }

    private static PrimaryFileResponse getPrimaryFileResponse(AgentStatus agentStatus) {
        return new PrimaryFileResponse("agent-id",
                200,
                agentStatus,
                "http://example.com/.well-known/pki-validation/fileauth.txt",
                "http://example.com/.well-known/pki-validation/fileauth.txt",
                "some-token-value");
    }
}