package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.methods.file.validate.MpicFileDetails;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
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

    public MpicFileDetails getMpicFileDetails(List<String> fileUrls) {
        MpicFileDetails firstMpicFileDetails = null;
        for (String fileUrl : fileUrls) {
            MpicFileResponse mpicFileResponse = mpicClient.getMpicFileResponse(fileUrl);
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

    private MpicFileDetails mapToMpicFileDetailsWithErrorCheck(MpicFileResponse mpicFileResponse, String fileUrl) {

        if (mpicFileResponse == null ||
                mpicFileResponse.primaryFileResponse() == null ||
                mpicFileResponse.mpicStatus() == MpicStatus.ERROR) {
            MpicDetails mpicDetails = new MpicDetails(false,
                    null,
                    0,
                    0,
                    Collections.emptyMap());
            log.info("event_id={} mpic_file_response={}", LogEvents.MPIC_INVALID_RESPONSE, mpicFileResponse);
            return new MpicFileDetails(mpicDetails,
                    fileUrl,
                    null,
                    500,
                    DcvError.MPIC_INVALID_RESPONSE);
        }

        if (!FILE_SUCCESS.equals(mpicFileResponse.primaryFileResponse().agentStatus())) {
            DcvError dcvError = switch (mpicFileResponse.primaryFileResponse().agentStatus()) {
                case FILE_BAD_REQUEST,
                     FILE_CLIENT_ERROR,
                     FILE_REQUEST_TIMEOUT -> DcvError.FILE_VALIDATION_CLIENT_ERROR;
                case FILE_BAD_RESPONSE,
                     FILE_NOT_FOUND,
                     FILE_TOO_LARGE -> DcvError.FILE_VALIDATION_INVALID_CONTENT;
                case FILE_SERVER_ERROR -> DcvError.FILE_VALIDATION_INVALID_STATUS_CODE;
                default -> DcvError.MPIC_INVALID_RESPONSE;
            };
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.FILE_VALIDATION_BAD_RESPONSE, mpicFileResponse.primaryFileResponse().agentStatus(), dcvError);
            return mapToMpicFileDetails(mpicFileResponse, fileUrl, dcvError);
        }

        if (mpicFileResponse.primaryFileResponse().fileContents() == null ||
                mpicFileResponse.primaryFileResponse().fileContents().isEmpty()) {
            DcvError dcvError = DcvError.FILE_VALIDATION_EMPTY_RESPONSE;
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.FILE_VALIDATION_BAD_RESPONSE, mpicFileResponse.primaryFileResponse().agentStatus(), dcvError);
            return mapToMpicFileDetails(mpicFileResponse, fileUrl, dcvError);
        }

        if (mpicClient.shouldEnforceCorroboration() && mpicFileResponse.mpicStatus() == MpicStatus.NON_CORROBORATED) {
            DcvError dcvError = DcvError.MPIC_CORROBORATION_ERROR;
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.FILE_VALIDATION_BAD_RESPONSE, mpicFileResponse.primaryFileResponse().agentStatus(), dcvError);
            return mapToMpicFileDetails(mpicFileResponse, fileUrl, dcvError);
        }

        log.info("event_id={} agent_status={} file_url={}",
                LogEvents.FILE_VALIDATION_RESPONSE, mpicFileResponse.primaryFileResponse().agentStatus(), fileUrl);
        return mapToMpicFileDetails(mpicFileResponse, fileUrl, null);
    }

    private MpicFileDetails mapToMpicFileDetails(MpicFileResponse mpicFileResponse, String fileUrl, DcvError dcvError) {
        boolean corroborated = dcvError != null && MpicStatus.CORROBORATED.equals(mpicFileResponse.mpicStatus());
        String primaryAgentId = mpicFileResponse.primaryFileResponse().agentId();
        int serversChecked = mpicFileResponse.secondaryFileResponses().size() + 1;
        long numCorroborated = mpicFileResponse.secondaryFileResponses().stream()
                .filter(SecondaryFileResponse::corroborates)
                .count();
        Map<String, Boolean> agentIdToCorroboration = mpicFileResponse.secondaryFileResponses().stream()
                .collect(HashMap::new,
                        (map, response) -> map.put(response.agentId(), response.corroborates()),
                        HashMap::putAll);

        MpicDetails mpicDetails = new MpicDetails(corroborated,
                primaryAgentId,
                serversChecked,
                numCorroborated,
                agentIdToCorroboration);

        return new MpicFileDetails(mpicDetails,
                fileUrl,
                mpicFileResponse.primaryFileResponse().fileContents(),
                mpicFileResponse.primaryFileResponse().statusCode(),
                dcvError);
    }
}
