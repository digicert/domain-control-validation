package com.digicert.validation.methods.file.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicFileService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
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
        List<String> fileUrls = getFileUrls(validationRequest);
        ChallengeType challengeType = validationRequest.getChallengeType();

        MpicFileDetails mpicFileDetails = mpicFileService.getMpicFileDetails(fileUrls);
        ChallengeValidationResponse challengeValidationResponse = null;

        if (mpicFileDetails.dcvError() == null) {
            String fileContent = mpicFileDetails.fileContents();
            challengeValidationResponse = getValidChallengeResponse(validationRequest, fileContent);
        }

        return buildFileValidationResponse(challengeValidationResponse, mpicFileDetails, challengeType, validationRequest);
    }

    private FileValidationResponse buildFileValidationResponse(ChallengeValidationResponse challengeValidationResponse, MpicFileDetails mpicFileDetails, ChallengeType challengeType, FileValidationRequest validationRequest) {
        if (challengeValidationResponse == null) {
            DcvError dcvError = mpicFileDetails.dcvError() == null ? DcvError.FILE_VALIDATION_EMPTY_RESPONSE : mpicFileDetails.dcvError();
            return FileValidationResponse.builder()
                    .isValid(false)
                    .mpicDetails(mpicFileDetails.mpicDetails())
                    .domain(validationRequest.getDomain())
                    .fileUrl(mpicFileDetails.fileUrl())
                    .challengeType(challengeType)
                    .errors(Set.of(dcvError))
                    .build();
        }

        String validRandomValue = null;
        String validRequestToken = null;

        if (challengeType == ChallengeType.RANDOM_VALUE) {
            validRandomValue = challengeValidationResponse.challengeValue().orElse(null);
        } else {
            validRequestToken = challengeValidationResponse.challengeValue().orElse(null);
        }

        return FileValidationResponse.builder()
                .isValid(challengeValidationResponse.challengeValue().isPresent())
                .mpicDetails(mpicFileDetails.mpicDetails())
                .domain(validationRequest.getDomain())
                .fileUrl(mpicFileDetails.fileUrl())
                .challengeType(challengeType)
                .validRandomValue(validRandomValue)
                .validRequestToken(validRequestToken)
                .errors(challengeValidationResponse.errors())
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
            return List.of("https://" + domainPath, "http://" + domainPath);
        }
        else {
            return List.of("http://" + domainPath);
        }
    }
}