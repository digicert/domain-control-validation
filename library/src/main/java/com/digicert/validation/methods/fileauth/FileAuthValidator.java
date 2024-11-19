package com.digicert.validation.methods.fileauth;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationRequest;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationResponse;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationHandler;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationRequest;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationResponse;
import com.digicert.validation.random.RandomValueGenerator;
import com.digicert.validation.random.RandomValueVerifier;
import com.digicert.validation.utils.DomainNameUtils;
import com.digicert.validation.utils.FilenameUtils;
import com.digicert.validation.utils.StateValidationUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

/**
 * FileAuthValidator is a class that provides methods to prepare and validate files for domain validation.
 * <p>
 * This class implements Validation for {@link DcvMethod#BR_3_2_2_4_18} method. It is responsible for handling the preparation and validation
 * processes required for file-based domain control validation (DCV).
 */
@Slf4j
public class FileAuthValidator {

    /**
     * Utility class for generating random values
     * <p>
     * This utility class is used to generate random values that are required during the file-based domain validation process.
     */
    private final RandomValueGenerator randomValueGenerator;

    /**
     * Utility class for random value verification
     * <p>
     * This utility class is responsible for verifying the random values generated during the preparation phase. It ensures that
     * the random values meet the required entropy levels and have not expired.
     */
    private final RandomValueVerifier randomValueVerifier;

    /**
     * Utility class for domain name operations
     * <p>
     * This utility class provides various operations related to domain names, such as validation and manipulation.
     */
    private final DomainNameUtils domainNameUtils;

    /**
     * Handler for File Auth Validation
     * <p>
     * This handler is responsible for executing the file-based domain validation process.
     */
    private final FileAuthValidationHandler fileAuthValidationHandler;

    /**
     * File location based on the BR specifications
     * <p>
     *     This string is combined with the submitted domain name and file location to create the URL
     *     where the file will be placed.
     */
    private final static String FILE_LOCATION = "http://%s/.well-known/pki-validation/%s";

    /**
     * Default filename for the file authentication
     * <p>
     *     If no filename is specified in the request, the default filename specified in the dcvConfiguration will be used.
     */
    private final String defaultFilename;

    /**
     * Constructor for FileAuthValidator
     * <p>
     * Initializes the FileAuthValidator with the necessary dependencies and configurations provided by the {@link DcvContext}.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public FileAuthValidator(DcvContext dcvContext) {
        this.randomValueGenerator = dcvContext.get(RandomValueGenerator.class);
        this.randomValueVerifier = dcvContext.get(RandomValueVerifier.class);
        this.domainNameUtils = dcvContext.get(DomainNameUtils.class);
        this.fileAuthValidationHandler = dcvContext.get(FileAuthValidationHandler.class);
        this.defaultFilename = dcvContext.getDcvConfiguration().getFileAuthFilename();
    }

    /**
     * Prepare for file validation.
     * <p>
     * This method prepares for file domain validation by generating a random value if the secret type is {@link ChallengeType#RANDOM_VALUE}.
     * It verifies the preparation request and constructs a response containing the necessary information for the validation process.
     *
     * @param preparationRequest {@link FileAuthPreparationRequest} object containing the domain and secret type
     * @return {@link FileAuthPreparationResponse} object containing the random value and domain
     * @throws DcvException if the request is invalid. {@link InputException} when missing required fields.
     */
    public FileAuthPreparationResponse prepare(FileAuthPreparationRequest preparationRequest) throws DcvException {
        log.debug("fileAuthPreparation={}", preparationRequest);
        verifyFileAuthPreparation(preparationRequest);

        // Create and return the preparation response
        FileAuthPreparationResponse.FileAuthPreparationResponseBuilder responseBuilder = FileAuthPreparationResponse.builder()
                .domain(preparationRequest.domain())
                .challengeType(preparationRequest.challengeType())
                .fileLocation(getFileUrl(preparationRequest.domain(), preparationRequest.filename()))
                .validationState(new ValidationState(preparationRequest.domain(), Instant.now(), DcvMethod.BR_3_2_2_4_18));

        if (preparationRequest.challengeType() == ChallengeType.RANDOM_VALUE) {
            responseBuilder.randomValue(randomValueGenerator.generateRandomString());
        }

        log.debug("fileAuthPreparationResponse={}", responseBuilder);
        return responseBuilder.build();
    }

    /**
     * Perform File Auth validation
     * <p>
     * This method performs the file-based domain validation by verifying the provided validation request. It checks the validity
     * of the domain, secret type, random value, and validation state. If the validation is successful, it returns a {@link DomainValidationEvidence}
     * object containing the validation evidence. If the validation fails, it throws a {@link ValidationException} with the encountered errors.
     *
     * @param validationRequest {@link FileAuthValidationRequest} object containing the domain, secret type, random value and validation state
     * @return {@link DomainValidationEvidence} object containing the domain validation evidence
     * @throws ValidationException if the File Validation fails.
     * @throws InputException if the input parameters are invalid. See #verifyFileAuthValidationRequest
     */
    public DomainValidationEvidence validate(FileAuthValidationRequest validationRequest) throws DcvException {
        log.debug("fileAuthValidationRequest={}", validationRequest);

        verifyFileAuthValidationRequest(validationRequest);

        FileAuthValidationResponse fileAuthResponse = fileAuthValidationHandler.validate(validationRequest);

        if (fileAuthResponse.isValid()) {
            log.info("event_id={} domain={}", LogEvents.FILE_AUTH_VALIDATED, validationRequest.getDomain());
            return createDomainValidationEvidence(validationRequest, fileAuthResponse);
        } else {
            log.info("event_id={} domain={} file_auth_validation_response={}", LogEvents.FILE_AUTH_VALIDATION_FAILED, validationRequest.getDomain(), fileAuthResponse);
            throw new ValidationException(fileAuthResponse.errors());
        }
    }

    /**
     * Create the Domain Validation Evidence from the File Auth Validation Response
     * <p>
     * This method creates a {@link DomainValidationEvidence} object from the provided {@link FileAuthValidationRequest} and {@link FileAuthValidationResponse}.
     * It extracts the necessary information from the response and constructs the validation evidence, including the domain, DCV method, validation date,
     * file URL, random value, and found token.
     *
     * @param request The File Auth Validation Request
     * @param response The File Auth Validation Response
     * @return The Domain Validation Evidence
     */
    DomainValidationEvidence createDomainValidationEvidence(FileAuthValidationRequest request, FileAuthValidationResponse response) {
        return DomainValidationEvidence.builder()
                .domain(response.domain())
                .dcvMethod(request.getValidationState().dcvMethod())
                .validationDate(Instant.now())
                .fileUrl(response.fileUrl())
                .randomValue(response.validRandomValue())
                .foundToken(response.validToken())
                .build();
    }

    /**
     * Performs validation on the values in {@link FileAuthValidationRequest}.
     * <p>
     * This method validates the values in the provided {@link FileAuthValidationRequest}. It checks the domain, validation state,
     * and secret type, ensuring that all required fields are present and valid. For random values, it verifies the entropy and expiration.
     * For request tokens, it checks the presence of the token key and value.
     *
     * @param fileAuthValidationRequest The validation verification request
     * @throws DcvException If entropy level is insufficient. If the random value has expired.
     */
    void verifyFileAuthValidationRequest(FileAuthValidationRequest fileAuthValidationRequest) throws DcvException {

        domainNameUtils.validateDomainName(fileAuthValidationRequest.getDomain());
        StateValidationUtils.verifyValidationState(fileAuthValidationRequest.getValidationState(), DcvMethod.BR_3_2_2_4_18);

        switch (fileAuthValidationRequest.getChallengeType()) {
            case RANDOM_VALUE -> {
                Instant instant = fileAuthValidationRequest.getValidationState().prepareTime();
                randomValueVerifier.verifyRandomValue(fileAuthValidationRequest.getRandomValue(), instant);
            }
            case REQUEST_TOKEN -> {
                if(fileAuthValidationRequest.getTokenKey() == null) {
                    throw new InputException(DcvError.TOKEN_KEY_REQUIRED);
                }
                if (fileAuthValidationRequest.getTokenValue() == null) {
                    throw new InputException(DcvError.TOKEN_VALUE_REQUIRED);
                }
            }
        }
    }

    /**
     * Verify the File Auth Preparation Request
     * <p>
     * This method verifies the provided {@link FileAuthPreparationRequest} to ensure that all required fields are present and valid.
     * It checks the domain name and secret type, ensuring that the domain name is correctly formatted and does not contain wildcards.
     *
     * @param fileAuthPreparationRequest The File Auth Preparation Request
     * @throws DcvException if the request is invalid. {@link InputException} when missing required fields.
     */
    private void verifyFileAuthPreparation(FileAuthPreparationRequest fileAuthPreparationRequest) throws DcvException, IllegalArgumentException {
        domainNameUtils.validateDomainName(fileAuthPreparationRequest.domain());

        if (fileAuthPreparationRequest.challengeType() == null) {
            throw new InputException(DcvError.SECRET_TYPE_REQUIRED);
        }

        if (fileAuthPreparationRequest.filename() != null) {
            FilenameUtils.validateFilename(fileAuthPreparationRequest.filename());
        }

        if (fileAuthPreparationRequest.domain().startsWith("*.")) {
            throw new InputException(DcvError.DOMAIN_INVALID_WILDCARD_NOT_ALLOWED);
        }
    }

    /**
     * Generate a URL for the where file will be placed on the server
     * <p>
     * This method updates the required URL with the appropriate domain name and filename.
     *
     * @param domainName The domain name for which the file authentication is being prepared
     * @param fileName The name of the file to be used in the URL
     * @return The URL where the file will be placed
     */
    String getFileUrl(String domainName, String fileName) {
        if (StringUtils.isEmpty(fileName)) {
            fileName = defaultFilename;
        }
        return String.format(FILE_LOCATION, domainName, fileName);
    }
}