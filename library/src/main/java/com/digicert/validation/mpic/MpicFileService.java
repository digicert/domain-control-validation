package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.methods.file.validate.MpicFileDetails;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import com.digicert.validation.mpic.api.file.SecondaryFileResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.digicert.validation.mpic.api.AgentStatus.FILE_SUCCESS;

@Slf4j
public class MpicFileService {

    private MpicClientInterface mpicClient;

    /**
     * Constructs a new MpicService with the specified configuration.
     *
     * @param dcvContext context where we can find the necessary dependencies / configuration
     */
    public MpicFileService(DcvContext dcvContext) {
        this.mpicClient = dcvContext.get(MpicClientInterface.class);
    }

    /**
     * Retrieves MPIC file details for a list of file URLs.
     * It will return the first valid and corroborated MPIC response or the first MPIC response with an error.
     *
     * @param fileUrls    List of file URLs to validate
     * @param randomValue A random value that should be included in the file content for validation
     * @return MpicFileDetails containing the MPIC details, file URL, file contents, status code, and any errors encountered
     */
    public MpicFileDetails getMpicFileDetails(List<String> fileUrls, String randomValue) {
        MpicFileDetails firstMpicFileDetails = null;
        for (String fileUrl : fileUrls) {
            MpicFileResponse mpicFileResponse = mpicClient.getMpicFileResponse(fileUrl, randomValue);
            MpicFileDetails mpicFileDetails = mapToMpicFileDetailsWithErrorCheck(mpicFileResponse, fileUrl);
            if (mpicFileDetails.dcvError() == null) {
                // We have a valid and corroborated MPIC response
                // we can return it immediately
                return mpicFileDetails;
            } else {
                // Remember the first MPIC details with an dcvError to return later
                firstMpicFileDetails = firstMpicFileDetails == null ? mpicFileDetails : firstMpicFileDetails;
            }
        }

        // If we are here, there is no valid MPIC response for any of the domains
        // return the first MPIC details with an dcvError if available
        return firstMpicFileDetails;
    }

    /**
     * Retrieves MPIC file details for a single file URL.
     * It will return the MPIC response with any associated error.
     *
     * @param fileUrl           The file URL to validate
     * @param randomValue       A random value that should be included in the file content for validation
     * @return MpicFileDetails containing the MPIC details, file URL, file contents, status code, and any errors encountered
     */
    public MpicFileDetails getMpicFileDetails(String fileUrl, String randomValue) {
        MpicFileResponse mpicFileResponse = mpicClient.getMpicFileResponse(fileUrl, randomValue);
        return mapToMpicFileDetailsWithErrorCheck(mpicFileResponse, fileUrl);
    }

    /**
     * Retrieves the primary file response for a list of file URLs.
     * It will return the first valid primary file response or the first response with an error.
     *
     * @param fileUrls List of file URLs to validate
     * @return PrimaryFileResponse containing the primary file response details
     */
    public PrimaryFileResponse getPrimaryOnlyFileResponse(List<String> fileUrls) {
        PrimaryFileResponse firstResponse = null;
        for (String fileUrl : fileUrls) {
            PrimaryFileResponse primaryFileResponse = mpicClient.getPrimaryOnlyFileResponse(fileUrl);
            if (primaryFileResponse.agentStatus() == FILE_SUCCESS) {
                // We have a valid response
                // we can return it immediately
                return primaryFileResponse;
            } else {
                // Remember the first MPIC details with an dcvError to return later
                firstResponse = firstResponse == null ? primaryFileResponse : firstResponse;
            }
        }

        // If we are here, there is no valid MPIC response for any of the domains
        // return the first response with an error if available
        return firstResponse;
    }

    private MpicFileDetails mapToMpicFileDetailsWithErrorCheck(MpicFileResponse mpicFileResponse, String fileUrl) {

        if (mpicFileResponse == null ||
                mpicFileResponse.primaryFileResponse() == null ||
                mpicFileResponse.mpicStatus() == MpicStatus.ERROR) {
            MpicDetails mpicDetails = new MpicDetails(false,
                    null,
                    0,
                    0,
                    Collections.emptyMap(),
                    null);
            log.info("event_id={} mpic_file_response={}", LogEvents.MPIC_INVALID_RESPONSE, mpicFileResponse);
            return new MpicFileDetails(mpicDetails,
                    fileUrl,
                    null,
                    500,
                    DcvError.MPIC_INVALID_RESPONSE);
        }

        DcvError dcvError = findDcvErrorOrNull(mpicFileResponse);
        log.info("event_id={} agent_status={} file_url={} mpic_status={} dcv_error={}",
                LogEvents.FILE_VALIDATION_RESPONSE,
                mpicFileResponse.primaryFileResponse().agentStatus(),
                fileUrl,
                mpicFileResponse.mpicStatus(),
                dcvError);
        return mapToMpicFileDetails(mpicFileResponse, fileUrl, dcvError);
    }

    private DcvError findDcvErrorOrNull(MpicFileResponse mpicFileResponse) {
        DcvError dcvError = null;
        if (!FILE_SUCCESS.equals(mpicFileResponse.primaryFileResponse().agentStatus())) {
            dcvError = mapAgentStatusToDcvError(mpicFileResponse.primaryFileResponse().agentStatus());
        }
        else if (mpicFileResponse.primaryFileResponse().fileContents() == null || mpicFileResponse.primaryFileResponse().fileContents().isEmpty()) {
            dcvError = DcvError.FILE_VALIDATION_EMPTY_RESPONSE;
        }
        else if (mpicFileResponse.mpicStatus() == MpicStatus.VALUE_NOT_FOUND || mpicFileResponse.mpicStatus() == MpicStatus.PRIMARY_AGENT_FAILURE) {
            dcvError = DcvError.FILE_VALIDATION_NOT_FOUND;
        }
        else if (mpicFileResponse.mpicStatus() == MpicStatus.NON_CORROBORATED && mpicClient.shouldEnforceCorroboration()) {
            dcvError = DcvError.MPIC_CORROBORATION_ERROR;
        }
        return dcvError;
    }

    public static DcvError mapAgentStatusToDcvError(AgentStatus agentStatus) {
        return switch (agentStatus) {
            case FILE_BAD_REQUEST -> DcvError.FILE_VALIDATION_BAD_REQUEST;
            case FILE_CLIENT_ERROR -> DcvError.FILE_VALIDATION_CLIENT_ERROR;
            case FILE_REQUEST_TIMEOUT -> DcvError.FILE_VALIDATION_TIMEOUT;
            case FILE_BAD_RESPONSE -> DcvError.FILE_VALIDATION_BAD_RESPONSE;
            case FILE_NOT_FOUND -> DcvError.FILE_VALIDATION_NOT_FOUND;
            case FILE_TOO_LARGE -> DcvError.FILE_VALIDATION_INVALID_CONTENT;
            case FILE_SERVER_ERROR -> DcvError.FILE_VALIDATION_INVALID_STATUS_CODE;
            default -> DcvError.MPIC_INVALID_RESPONSE;
        };
    }

    private MpicFileDetails mapToMpicFileDetails(MpicFileResponse mpicFileResponse, String fileUrl, DcvError dcvError) {
        boolean corroborated = MpicStatus.CORROBORATED.equals(mpicFileResponse.mpicStatus());
        String primaryAgentId = mpicFileResponse.primaryFileResponse().agentId();
        int numSecondariesChecked = mpicFileResponse.secondaryFileResponses().size();
        long numCorroborated = mpicFileResponse.secondaryFileResponses().stream()
                .filter(SecondaryFileResponse::corroborates)
                .count();
        Map<String, Boolean> agentIdToCorroboration = mpicFileResponse.secondaryFileResponses().stream()
                .collect(HashMap::new,
                        (map, response) -> map.put(response.agentId(), response.corroborates()),
                        HashMap::putAll);

        MpicDetails mpicDetails = new MpicDetails(corroborated,
                primaryAgentId,
                numSecondariesChecked,
                numCorroborated,
                agentIdToCorroboration,
                null);

        return new MpicFileDetails(mpicDetails,
                fileUrl,
                mpicFileResponse.primaryFileResponse().fileContents(),
                mpicFileResponse.primaryFileResponse().statusCode(),
                dcvError);
    }
}
