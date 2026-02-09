package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.file.validate.MpicFileDetails;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnssecStatus;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import com.digicert.validation.mpic.api.file.SecondaryFileResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static com.digicert.validation.mpic.api.AgentStatus.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MpicFileServiceTest {

    private DcvContext dcvContext;
    private MpicClientInterface mpicClient;
    private MpicFileService mpicFileService;

    @BeforeEach
    void setUp() {
        dcvContext = mock(DcvContext.class);
        mpicClient = mock(MpicClientInterface.class);
        when(dcvContext.get(MpicClientInterface.class)).thenReturn(mpicClient);
        mpicFileService = new MpicFileService(dcvContext);
    }

    private MpicFileResponse createMpicFileResponse(PrimaryFileResponse primary,
                                                    List<SecondaryFileResponse> secondary,
                                                    MpicStatus mpicStatus) {
        return new MpicFileResponse(primary, secondary, mpicStatus, 2, null );
    }

    @Test
    void returnsInvalidResponseWhenMpicFileResponseIsNull() {
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(null);
        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.MPIC_INVALID_RESPONSE, details.dcvError());
        assertEquals("url", details.fileUrl());
    }

    @Test
    void returnsInvalidResponseWhenPrimaryFileResponseIsNull() {
        MpicFileResponse response = createMpicFileResponse(null, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);
        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.MPIC_INVALID_RESPONSE, details.dcvError());
    }

    @Test
    void returnsInvalidResponseWhenMpicStatusIsError() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.ERROR);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);
        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.MPIC_INVALID_RESPONSE, details.dcvError());
    }

    @Test
    void returnsMappedErrorWhenAgentStatusIsNotFileSuccess() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 400, FILE_CLIENT_ERROR, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.FILE_VALIDATION_CLIENT_ERROR, details.dcvError());
    }

    @Test
    void returnsEmptyResponseErrorWhenFileContentsIsNull() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", null);
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.FILE_VALIDATION_EMPTY_RESPONSE, details.dcvError());
    }

    @Test
    void returnsEmptyResponseErrorWhenFileContentsIsEmpty() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.FILE_VALIDATION_EMPTY_RESPONSE, details.dcvError());
    }

    @Test
    void returnsCorroborationErrorWhenStatusNonCorroborated() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.NON_CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertEquals(DcvError.MPIC_CORROBORATION_ERROR, details.dcvError());
    }

    @Test
    void returnsValidWhenAllIsGood() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        SecondaryFileResponse secondary = new SecondaryFileResponse("agent2", 200, FILE_SUCCESS, true);
        MpicFileResponse response = createMpicFileResponse(primary, List.of(secondary), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");
        assertNull(details.dcvError());
        assertEquals("file-contents", details.fileContents());
        assertEquals("url", details.fileUrl());
        assertEquals(200, details.statusCode());
        assertNotNull(details.mpicDetails());
        assertTrue(details.mpicDetails().corroborated());
        assertEquals("agent1", details.mpicDetails().primaryAgentId());
        assertEquals(1, details.mpicDetails().secondaryServersChecked());
        assertEquals(1, details.mpicDetails().secondaryServersCorroborated());
        assertTrue(details.mpicDetails().agentIdToCorroboration().get("agent2"));
    }

    @Test
    void returnsFirstValidOrFirstErrorForMultipleUrls() {
        // First URL returns error, second is valid
        PrimaryFileResponse errorPrimary = new PrimaryFileResponse("agent1", 400, FILE_CLIENT_ERROR, "abc", "abc", "file-contents");
        MpicFileResponse errorResponse = createMpicFileResponse(errorPrimary, Collections.emptyList(), MpicStatus.CORROBORATED);

        PrimaryFileResponse validPrimary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        MpicFileResponse validResponse = createMpicFileResponse(validPrimary, Collections.emptyList(), MpicStatus.CORROBORATED);

        when(mpicClient.getMpicFileResponse("url1", "randomValue")).thenReturn(errorResponse);
        when(mpicClient.getMpicFileResponse("url2", "randomValue")).thenReturn(validResponse);

        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url1", "url2"), "randomValue");
        assertNull(details.dcvError());
        assertEquals("file-contents", details.fileContents());

        // Now, both error
        when(mpicClient.getMpicFileResponse("url2", "randomValue")).thenReturn(errorResponse);
        MpicFileDetails errorDetails = mpicFileService.getMpicFileDetails(List.of("url1", "url2"), "randomValue");
        assertEquals(DcvError.FILE_VALIDATION_CLIENT_ERROR, errorDetails.dcvError());
    }

    @ParameterizedTest
    @MethodSource("agentStatusToErrorMapping")
    void mapsDifferentAgentStatusesToCorrectDcvErrors(AgentStatus agentStatus, DcvError expectedError) {
        // Setup
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 400, agentStatus, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        // Execute
        MpicFileDetails details = mpicFileService.getMpicFileDetails(List.of("url"), "randomValue");

        // Verify
        assertEquals(expectedError, details.dcvError());
        assertEquals("url", details.fileUrl());
        assertEquals("file-contents", details.fileContents());
    }

    @Test
    void getMpicFileSingleUrlSuccess(){
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        SecondaryFileResponse secondary = new SecondaryFileResponse("agent2", 200, FILE_SUCCESS, true);
        MpicFileResponse response = createMpicFileResponse(primary, List.of(secondary), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails("url", "randomValue");
        assertNull(details.dcvError());
        assertEquals("file-contents", details.fileContents());
        assertEquals("url", details.fileUrl());
        assertEquals(200, details.statusCode());
        assertNotNull(details.mpicDetails());
        assertTrue(details.mpicDetails().corroborated());
        assertEquals("agent1", details.mpicDetails().primaryAgentId());
        assertEquals(1, details.mpicDetails().secondaryServersChecked());
        assertEquals(1, details.mpicDetails().secondaryServersCorroborated());
        assertTrue(details.mpicDetails().agentIdToCorroboration().get("agent2"));
    }

    @Test
    void getMpicFileSingleUrlErrorValueNotFound(){
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.VALUE_NOT_FOUND);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails("url", "randomValue");
        assertEquals(DcvError.FILE_VALIDATION_NOT_FOUND, details.dcvError());
        assertEquals("url", details.fileUrl());
    }

    @Test
    void getPrimaryOnlyFileResponseFileSuccess(){
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        when(mpicClient.getPrimaryOnlyFileResponse("url")).thenReturn(primary);

        PrimaryFileResponse response = mpicFileService.getPrimaryOnlyFileResponse(List.of("url"));
        assertEquals(primary, response);
    }

    @Test
    void getPrimaryOnlyFileResponseFileFirstResultIsError(){
        PrimaryFileResponse primary1 = new PrimaryFileResponse("agent1", 500, FILE_CLIENT_ERROR, "abc", "abc", "bad-contents");
        when(mpicClient.getPrimaryOnlyFileResponse("url1")).thenReturn(primary1);
        PrimaryFileResponse primary2 = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        when(mpicClient.getPrimaryOnlyFileResponse("url2")).thenReturn(primary2);

        PrimaryFileResponse response = mpicFileService.getPrimaryOnlyFileResponse(List.of("url1", "url2"));
        assertEquals(primary2, response);
    }

    @Test
    void getPrimaryOnlyFileResponseAllResultsAreErrors(){
        PrimaryFileResponse primary1 = new PrimaryFileResponse("agent1", 500, FILE_CLIENT_ERROR, "abc", "abc", "bad-contents");
        when(mpicClient.getPrimaryOnlyFileResponse("url1")).thenReturn(primary1);
        PrimaryFileResponse primary2 = new PrimaryFileResponse("agent1", 400, FILE_BAD_REQUEST, "abc", "abc", "worse-contents");
        when(mpicClient.getPrimaryOnlyFileResponse("url2")).thenReturn(primary2);

        PrimaryFileResponse response = mpicFileService.getPrimaryOnlyFileResponse(List.of("url1", "url2"));
        assertEquals(primary1, response);
    }

    @Test
    void dnssecDetailsIsAlwaysNotCheckedForFileValidation() {
        PrimaryFileResponse primary = new PrimaryFileResponse("agent1", 200, FILE_SUCCESS, "abc", "abc", "file-contents");
        MpicFileResponse response = createMpicFileResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicFileResponse("url", "randomValue")).thenReturn(response);

        MpicFileDetails details = mpicFileService.getMpicFileDetails("url", "randomValue");

        assertNotNull(details.mpicDetails().dnssecDetails());
        assertEquals(DnssecStatus.NOT_CHECKED, details.mpicDetails().dnssecDetails().dnssecStatus());
        assertNull(details.mpicDetails().dnssecDetails().dnssecError());
        assertNull(details.mpicDetails().dnssecDetails().errorLocation());
        assertNull(details.mpicDetails().dnssecDetails().errorDetails());
    }

    static Stream<Arguments> agentStatusToErrorMapping() {
        return Stream.of(
                Arguments.of(FILE_BAD_REQUEST, DcvError.FILE_VALIDATION_BAD_REQUEST),
                Arguments.of(FILE_CLIENT_ERROR, DcvError.FILE_VALIDATION_CLIENT_ERROR),
                Arguments.of(FILE_REQUEST_TIMEOUT, DcvError.FILE_VALIDATION_TIMEOUT),
                Arguments.of(FILE_BAD_RESPONSE, DcvError.FILE_VALIDATION_BAD_RESPONSE),
                Arguments.of(FILE_NOT_FOUND, DcvError.FILE_VALIDATION_NOT_FOUND),
                Arguments.of(FILE_TOO_LARGE, DcvError.FILE_VALIDATION_INVALID_CONTENT),
                Arguments.of(FILE_SERVER_ERROR, DcvError.FILE_VALIDATION_INVALID_STATUS_CODE),

                // This should never happen, but we handle it gracefully
                Arguments.of(DNS_LOOKUP_BAD_REQUEST, DcvError.MPIC_INVALID_RESPONSE)
        );
    }
}
