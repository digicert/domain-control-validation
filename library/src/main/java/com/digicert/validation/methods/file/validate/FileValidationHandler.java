package com.digicert.validation.methods.file.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicFileService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Handles the validation of file-based domain control validation (DCV) requests.
 * <p>
 * This class is responsible for managing the validation process of file-based DCV requests. It interacts with various
 * components such as the file validation client, random value validator, and request token validator to ensure that the
 * validation process is carried out correctly. The class provides methods to set up the necessary clients, validate
 * the requests, and retrieve files from the required URLs.
 */
@Slf4j
public class FileValidationHandler {

    /** The MPIC file service used to fetch file validation details. */
    private final MpicFileService mpicFileService;

    /** The random value validator used to confirm that the file text contains the expected random value. */
    private final RandomValueValidator randomValueValidator;

    /** The request token validator used to confirm that the file text contains a valid request token. */
    private final RequestTokenValidator requestTokenValidator;

    /** The path to the file containing the challenge value. */
    private static final String FILE_PATH = "/.well-known/pki-validation/";

    /** The default file validation filename. */
    private final String defaultFileValidationFilename;

    /** The flag to check if the file validation request should be made over HTTPS. */
    private final boolean fileValidationCheckHttps;

    /** The flag to check if HTTPS should be tried first for file validation requests. */
    private final boolean fileValidationCheckHttpsFirst;

    /**
     * Constructs a new FileValidationHandler with the specified configuration.
     * <p>
     * This constructor initializes the FileValidationHandler with the necessary dependencies and configuration
     * settings. It retrieves the required clients and validators from the provided DcvContext and sets up the default
     * file validation filename.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public FileValidationHandler(DcvContext dcvContext) {
        mpicFileService = dcvContext.get(MpicFileService.class);
        randomValueValidator = dcvContext.get(RandomValueValidator.class);
        requestTokenValidator = dcvContext.get(RequestTokenValidator.class);

        defaultFileValidationFilename = dcvContext.getDcvConfiguration().getFileValidationFilename();
        fileValidationCheckHttps = dcvContext.getDcvConfiguration().getFileValidationCheckHttps();
        fileValidationCheckHttpsFirst = dcvContext.getDcvConfiguration().getFileValidationCheckHttpsFirst();
    }

    /**
     * Validates the file-based domain control validation (DCV) request.
     * <p>
     * This method processes the file-based DCV request by validating the provided file URLs and checking for errors.
     * It uses the file validation client to execute requests and retrieve responses, which are then validated
     * using the random value validator or request token validator. The method constructs a response based on the validation
     * results, indicating whether the validation was successful or not.
     *
     * @param validationRequest the file validation request
     * @return the file validation response
     */
    public FileValidationResponse validate(FileValidationRequest validationRequest) {
        switch (validationRequest.getChallengeType()) {
            case RANDOM_VALUE -> {
                return performValidationForRandomValue(validationRequest);
            }
            case REQUEST_TOKEN -> {
                return performValidationForRequestToken(validationRequest);
            }
        }

        // We should never get here because the challenge type is validated before this method is called
        return buildFileValidationResponse(
                new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.CHALLENGE_TYPE_REQUIRED)),
                null,
                validationRequest,
                null,
                null);
    }

    private FileValidationResponse performValidationForRandomValue(FileValidationRequest validationRequest) {
        List<String> fileUrls = getFileUrls(validationRequest);

        MpicFileDetails mpicFileDetails = mpicFileService.getMpicFileDetails(fileUrls, validationRequest.getRandomValue());
        ChallengeValidationResponse challengeResponse;

        if (mpicFileDetails.dcvError() == null) {
            String fileContent = mpicFileDetails.fileContents();
            challengeResponse = getValidChallengeResponse(validationRequest, fileContent);
        } else {
            challengeResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(mpicFileDetails.dcvError()));
        }

        return buildFileValidationResponse(challengeResponse,
                validationRequest.getChallengeType(),
                validationRequest,
                mpicFileDetails.mpicDetails(),
                mpicFileDetails.fileUrl());
    }

    private FileValidationResponse performValidationForRequestToken(FileValidationRequest validationRequest) {
        // First, get the primary file response to see if we can find a valid request token
        List<String> fileUrls = getFileUrls(validationRequest);
        PrimaryFileResponse primaryFileResponse = mpicFileService.getPrimaryOnlyFileResponse(fileUrls);

        if (primaryFileResponse == null) {
            DcvError dcvError = DcvError.FILE_VALIDATION_INVALID_STATUS_CODE;
            return buildFileValidationResponse(
                    new ChallengeValidationResponse(Optional.empty(), Set.of(dcvError)),
                    validationRequest.getChallengeType(),
                    validationRequest,
                    null,
                    null);
        }

        String foundFileUrl = primaryFileResponse.fileUrl();
        if (primaryFileResponse.agentStatus() != AgentStatus.FILE_SUCCESS) {
            DcvError dcvError = MpicFileService.mapAgentStatusToDcvError(primaryFileResponse.agentStatus());
            return buildFileValidationResponse(
                    new ChallengeValidationResponse(Optional.empty(), Set.of(dcvError)),
                    validationRequest.getChallengeType(),
                    validationRequest,
                    null,
                    foundFileUrl);
        }

        // Validate the primary file response for a valid request token
        ChallengeValidationResponse challengeResponse = getValidChallengeResponse(validationRequest, primaryFileResponse.fileContents());
        if (challengeResponse.challengeValue().isPresent()) {
            // We have a valid request token in the primary file response
            // Make another call to MPIC to get the corroborated response
            MpicFileDetails mpicFileDetails = mpicFileService.getMpicFileDetails(foundFileUrl, challengeResponse.challengeValue().get());
            if (mpicFileDetails.dcvError() == null) {
                challengeResponse = getValidChallengeResponse(validationRequest, mpicFileDetails.fileContents());
            } else {
                challengeResponse = new ChallengeValidationResponse(Optional.empty(), Set.of(mpicFileDetails.dcvError()));
            }
            return buildFileValidationResponse(challengeResponse,
                    validationRequest.getChallengeType(),
                    validationRequest,
                    mpicFileDetails.mpicDetails(),
                    mpicFileDetails.fileUrl());
        }

        return buildFileValidationResponse(challengeResponse,
                validationRequest.getChallengeType(),
                validationRequest,
                null,
                foundFileUrl);
    }

    private FileValidationResponse buildFileValidationResponse(ChallengeValidationResponse challengeResponse,
                                                               ChallengeType challengeType,
                                                               FileValidationRequest validationRequest,
                                                               MpicDetails mpicDetails,
                                                               String fileUrl) {
        String validRandomValue = null;
        String validRequestToken = null;

        if (ChallengeType.RANDOM_VALUE.equals(challengeType)) {
            validRandomValue = challengeResponse.challengeValue().orElse(null);
        } else {
            validRequestToken = challengeResponse.challengeValue().orElse(null);
        }

        return FileValidationResponse.builder()
                .isValid(challengeResponse.challengeValue().isPresent())
                .mpicDetails(mpicDetails)
                .domain(validationRequest.getDomain())
                .fileUrl(fileUrl)
                .challengeType(challengeType)
                .validRandomValue(validRandomValue)
                .validRequestToken(validRequestToken)
                .errors(challengeResponse.errors())
                .build();
    }


    /**
     * Validates the presence of the random value or a valid request token in the provided file content.
     *
     * @param fileValidationRequest the file validation request
     * @param fileContent the content of the file where the challenge response should be found
     * @return ChallengeValidationResponse containing a valid challenge response or a set of errors
     */
    private ChallengeValidationResponse getValidChallengeResponse(FileValidationRequest fileValidationRequest, String fileContent) {
        return switch (fileValidationRequest.getChallengeType()) {
            case RANDOM_VALUE -> randomValueValidator.validate(fileValidationRequest.getRandomValue(), fileContent);
            case REQUEST_TOKEN -> requestTokenValidator.validate(fileValidationRequest.getRequestTokenData(), fileContent);
        };
    }

    /**
     * Retrieves the list of file URLs for the file-based domain control validation (DCV) request.
     * <p>
     * This method constructs the list of file URLs that will be used in the file-based DCV request. It uses the domain
     * and filename provided in the validation request to create the URLs. If no specific filename is provided, the
     * default file validation filename is used. If the `fileValidationCheckHttps` flag is true it will return a
     * list using both HTTP and HTTPS protocols, otherwise it will return a list that only includes HTTP.
     *
     * @param fileValidationRequest the file validation request
     * @return the list of file URLs
     */
    public List<String> getFileUrls(FileValidationRequest fileValidationRequest) {
        String domainPath;
        if (StringUtils.isNotBlank(fileValidationRequest.getFilename())) {
            domainPath = fileValidationRequest.getDomain() + FILE_PATH + fileValidationRequest.getFilename();
        } else {
            domainPath = fileValidationRequest.getDomain() + FILE_PATH + defaultFileValidationFilename;
        }
        if (fileValidationCheckHttps) {
            if (fileValidationCheckHttpsFirst) {
                return List.of("https://" + domainPath, "http://" + domainPath);
            } else {
                return List.of("http://" + domainPath, "https://" + domainPath);
            }
        }
        else {
            return List.of("http://" + domainPath);
        }
    }
}