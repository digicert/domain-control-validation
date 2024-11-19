package com.digicert.validation.methods.fileauth.validate;

import java.util.*;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.secrets.ChallengeValidationResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import com.digicert.validation.client.fileauth.FileAuthClient;
import com.digicert.validation.client.fileauth.FileAuthClientResponse;
import com.digicert.validation.secrets.RandomValueValidator;
import com.digicert.validation.secrets.TokenValidator;

/**
 * Handles the validation of file-based domain control validation (DCV) requests.
 * <p>
 * This class is responsible for managing the validation process of file-based DCV requests. It interacts with various
 * components such as the file authentication client, random value validator, and token validator to ensure that the
 * validation process is carried out correctly. The class provides methods to set up the necessary clients, validate
 * the requests, and retrieve the required file URLs.
 */
@Slf4j
public class FileAuthValidationHandler {

    /** The file authentication client. */
    private FileAuthClient fileAuthClient;

    /**
     * The random value validator.
     * <p>
     * This validator is used to validate the random values used in the file-based DCV process. It ensures that the
     * random values are correct and match the expected values. This is crucial for maintaining the security and
     * integrity of the validation process, as incorrect random values can lead to validation failures.
     */
    private final RandomValueValidator randomValueValidator;

    /** The token validator. */
    private final TokenValidator tokenValidator;

    /** The path to the token. */
    private static final String TOKEN_PATH = "/.well-known/pki-validation/";

    /** The default file authentication filename. */
    private final String defaultFileAuthFilename;

    /** The flag to check if the file authentication request should be made over HTTPS. */
    private final boolean fileAuthCheckHttps;

    /**
     * Constructs a new FileAuthValidationHandler with the specified configuration.
     * <p>
     * This constructor initializes the FileAuthValidationHandler with the necessary dependencies and configuration
     * settings. It retrieves the required clients and validators from the provided DcvContext and sets up the default
     * file authentication filename.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public FileAuthValidationHandler(DcvContext dcvContext) {
        fileAuthClient = dcvContext.get(FileAuthClient.class);
        randomValueValidator = dcvContext.get(RandomValueValidator.class);
        tokenValidator = dcvContext.get(TokenValidator.class);

        defaultFileAuthFilename = dcvContext.getDcvConfiguration().getFileAuthFilename();
        fileAuthCheckHttps = dcvContext.getDcvConfiguration().getFileAuthCheckHttps();
    }

    /**
     * Validates the file-based domain control validation (DCV) request.
     * <p>
     * This method processes the file-based DCV request by validating the provided file URLs and checking for errors.
     * It uses the file authentication client to execute requests and retrieve responses, which are then validated
     * using the random value validator and token validator. The method constructs a response based on the validation
     * results, indicating whether the validation was successful or not.
     *
     * @param validationRequest the file authentication validation request
     * @return the file authentication validation response
     */
    public FileAuthValidationResponse validate(FileAuthValidationRequest validationRequest) {
        List<String> fileUrls = getFileUrls(validationRequest);
        ChallengeType challengeType = validationRequest.getChallengeType();
        Set<DcvError> errors = new HashSet<>();

        for (String fileUrl : fileUrls) {
            FileAuthClientResponse fileAuthClientResponse = fileAuthClient.executeRequest(fileUrl);

            // Check and find errors in the file authentication response
            Optional<DcvError> responseError =  getErrorsFromFileAuthResponse(fileAuthClientResponse);
            if (responseError.isPresent()) {
                errors.add(responseError.get());
                continue;
            }

            // Check and find errors in the token validation response
            ChallengeValidationResponse challengeValidationResponse = getValidSecret(validationRequest, fileAuthClientResponse.getFileContent());
            if (challengeValidationResponse.token().isEmpty() && !challengeValidationResponse.errors().isEmpty()) {
                errors.addAll(challengeValidationResponse.errors());
                continue;
            }

            FileAuthValidationResponse.FileAuthValidationResponseBuilder responseBuilder = FileAuthValidationResponse.builder()
                    .isValid(challengeValidationResponse.token().isPresent())
                    .domain(validationRequest.getDomain())
                    .fileUrl(fileUrl)
                    .challengeType(challengeType);

            switch (challengeType) {
                case RANDOM_VALUE -> responseBuilder.validRandomValue(challengeValidationResponse.token().orElse(null));
                case REQUEST_TOKEN -> responseBuilder.validToken(challengeValidationResponse.token().orElse(null));
            }

            FileAuthValidationResponse response = responseBuilder.build();
            if (response.isValid()) {
                return response;
            }
        }

        return FileAuthValidationResponse.builder()
                .isValid(false)
                .domain(validationRequest.getDomain())
                .fileUrl(fileUrls.getFirst())
                .challengeType(challengeType)
                .errors(errors)
                .build();
    }

    /**
     * Retrieves the valid secret or null if the validation fails.
     *
     * @param fileAuthValidationRequest the file authentication validation request
     * @param fileContent the content of the file where the secret can be found
     * @return TokenValidatorResponse with a valid secret or null with populated errors if the validation fails.
     */
    private ChallengeValidationResponse getValidSecret(FileAuthValidationRequest fileAuthValidationRequest, String fileContent) {
        return switch (fileAuthValidationRequest.getChallengeType()) {
            case RANDOM_VALUE -> randomValueValidator.validate(fileAuthValidationRequest.getRandomValue(), fileContent);
            case REQUEST_TOKEN -> tokenValidator.validate(fileAuthValidationRequest.getTokenKey(), fileAuthValidationRequest.getTokenValue(), fileContent);
        };
    }

    /**
     * Checks if the file authentication response is valid.
     *
     * @param fileAuthClientResponse the file authentication client response
     * @return empty list if valid, otherwise a list of errors
     */
    private Optional<DcvError> getErrorsFromFileAuthResponse(FileAuthClientResponse fileAuthClientResponse) {

        if (fileAuthClientResponse.getException() != null) {
            log.info("event_id={} error={} exception_message={}",
                    LogEvents.FILE_AUTH_BAD_RESPONSE,
                    fileAuthClientResponse.getDcvError(),
                    fileAuthClientResponse.getException().getMessage());
            return Optional.of(fileAuthClientResponse.getDcvError());
        }

        // Although the BRs allow for any 2xx level response, the expectation is that the response will be 200.
        // https://tools.ietf.org/html/rfc7231#section-6.3.1
        if (fileAuthClientResponse.getStatusCode() != 200) {
            log.info("event_id={} error={} status_code={}",
                    LogEvents.FILE_AUTH_BAD_RESPONSE,
                    DcvError.FILE_AUTH_INVALID_STATUS_CODE,
                    fileAuthClientResponse.getStatusCode());

            return Optional.of(DcvError.FILE_AUTH_INVALID_STATUS_CODE);
        }

        if (StringUtils.isEmpty(fileAuthClientResponse.getFileContent())) {
            log.info("event_id={} error={} status_code={}",
                    LogEvents.FILE_AUTH_BAD_RESPONSE,
                    DcvError.FILE_AUTH_EMPTY_RESPONSE,
                    fileAuthClientResponse.getStatusCode());

            return Optional.of(DcvError.FILE_AUTH_EMPTY_RESPONSE);
        }

        return Optional.empty();
    }

    /**
     * Retrieves the list of file URLs for the file-based domain control validation (DCV) request.
     * <p>
     * This method constructs the list of file URLs that will be used in the file-based DCV request. It uses the domain
     * and filename provided in the validation request to create the URLs. If no specific filename is provided, the
     * default file authentication filename is used. The method returns a list of URLs with both HTTP and HTTPS
     * protocols, ensuring that the validation process can handle different types of requests.
     *
     * @param fileAuthValidationRequest the file authentication validation request
     * @return the list of file URLs
     */
    public List<String> getFileUrls(FileAuthValidationRequest fileAuthValidationRequest) {
        String domainPath;
        if (StringUtils.isNotBlank(fileAuthValidationRequest.getFilename())) {
            domainPath = fileAuthValidationRequest.getDomain() + TOKEN_PATH + fileAuthValidationRequest.getFilename();
        } else {
            domainPath = fileAuthValidationRequest.getDomain() + TOKEN_PATH + defaultFileAuthFilename;
        }
        if (fileAuthCheckHttps) {
            return List.of("http://" + domainPath, "https://" + domainPath);
        }
        else {
            return List.of("http://" + domainPath);
        }
    }
}