package com.digicert.validation.methods.acme;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.*;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.acme.prepare.AcmePreparation;
import com.digicert.validation.methods.acme.prepare.AcmePreparationResponse;
import com.digicert.validation.methods.acme.validate.AcmeValidationHandler;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import com.digicert.validation.methods.acme.validate.AcmeValidationResponse;
import com.digicert.validation.random.RandomValueGenerator;
import com.digicert.validation.random.RandomValueVerifier;
import com.digicert.validation.utils.DomainNameUtils;
import com.digicert.validation.utils.StateValidationUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

/**
 * AcmeValidator is a class that provides methods to prepare and validate domains using the ACME protocol.
 * <p>
 * This class implements Validation for the following methods:
 * <ul>
 *    <li>{@link DcvMethod#BR_3_2_2_4_7}</li>
 *    <li>{@link DcvMethod#BR_3_2_2_4_19}</li>
 * </ul>
 * <p>
 * The AcmeValidator class is responsible for handling the preparation and validation of domains using the ACME protocol.
 * It uses various utility classes and handlers to generate random values, verify domain names, and validate DNS record or HTTP files.
 * The class ensures that the ACME protocol is followed according to the specified ACME type requested.
 */
@Slf4j
public class AcmeValidator {

    /** Utility class for generating random values */
    private final RandomValueGenerator randomValueGenerator;

    /** Handler for ACME Validation */
    private final AcmeValidationHandler acmeValidationHandler;

    /** Utility class for random value verification */
    private final RandomValueVerifier randomValueVerifier;

    /** Utility class for domain name operations */
    private final DomainNameUtils domainNameUtils;

    /**
     * Constructor for AcmeValidator
     * <p>
     * This constructor initializes the AcmeValidator class with the necessary dependencies and configuration.
     * It retrieves the required instances from the provided DcvContext and sets up the utility classes and handlers for ACME validation.
     *
     * @param dcvContext context where we can find the necessary dependencies / configuration
     */
    public AcmeValidator(DcvContext dcvContext) {
        this.randomValueGenerator = dcvContext.get(RandomValueGenerator.class);
        this.acmeValidationHandler = dcvContext.get(AcmeValidationHandler.class);
        this.randomValueVerifier = dcvContext.get(RandomValueVerifier.class);
        this.domainNameUtils = dcvContext.get(DomainNameUtils.class);
    }

    /**
     * Prepare the domain for ACME validation
     * <p>
     * This method provides some preliminary checks for validation by verifying the domain can be requested
     * and then generating the necessary random value and setting up the validation state.
     *
     * @param acmePreparation {@link AcmePreparation} object containing the domain
     * @return {@link AcmePreparationResponse} object containing the random value and validation state
     * @throws DcvException if the ACME Preparation fails.
     */
    public AcmePreparationResponse prepare(AcmePreparation acmePreparation) throws DcvException {
        log.debug("acmePreparation={}", acmePreparation);

        verifyAcmePreparation(acmePreparation);

        AcmePreparationResponse acmePreparationResponse = AcmePreparationResponse.builder()
                .domain(acmePreparation.domain())
                .randomValue(randomValueGenerator.generateRandomString())
                // NOTE: The DCV Method is set to UNKNOWN here.
                // This is because the "prepare" step does not require a specific ACME Type. The AcmeType will be
                // provided when the "validate" step is called.
                .validationState(new ValidationState(acmePreparation.domain(), Instant.now(), DcvMethod.UNKNOWN))
                .build();

        log.debug("acmePreparationResponse={}", acmePreparationResponse);
        return acmePreparationResponse;
    }

    /**
     * Validate a domain using the ACME protocol
     * <p>
     * This method validates a domain by following the ACME protocol as defined in the provided request.
     * It checks the validity of the ACME validation request and constructs a DomainValidationEvidence object
     * if the validation is successful.
     *
     * @param acmeValidationRequest {@link AcmeValidationRequest} object containing the domain,
     *                                                           acme type,
     *                                                           acme thumbprint,
     *                                                           random value,
     *                                                           and Validation State
     * @return {@link DomainValidationEvidence} object containing the domain validation evidence
     * @throws ValidationException if the ACME Validation fails.
     * @throws InputException      if the input parameters are invalid.
     * <p>
     * See @{@link ValidationException} for more details
     */
    public DomainValidationEvidence validate(AcmeValidationRequest acmeValidationRequest) throws DcvException {
        log.debug("acmeValidationRequest={}", acmeValidationRequest);

        verifyAcmeValidationRequest(acmeValidationRequest);

        // Perform the ACME validation using the AcmeValidationHandler
        // This will throw an AcmeValidationException if the validation fails
        AcmeValidationResponse acmeValidationResponse = acmeValidationHandler.validate(acmeValidationRequest);

        // Set the timestamp of when the validation was completed
        // This time should be within a few ms of the validation succeeding
        Instant validationInstant = Instant.now();
        log.info("event_id={} domain={}", LogEvents.ACME_VALIDATION_SUCCESSFUL, acmeValidationRequest.getDomain());
        return createDomainValidationEvidence(acmeValidationRequest, acmeValidationResponse, validationInstant);
    }

    /**
     * Creates a DomainValidationEvidence object from the AcmeValidationRequest and AcmeValidationResponse
     *
     * @param acmeValidationRequest  The AcmeValidationRequest object containing the domain, acme type, acme thumbprint, random value, and validation state
     * @param acmeValidationResponse The AcmeValidationResponse object containing the MPIC details, and either the DNS record name or the file URL
     * @param validationInstant     The Instant when the validation was completed
     * @return DomainValidationEvidence object containing the domain validation evidence
     */
    private DomainValidationEvidence createDomainValidationEvidence(AcmeValidationRequest acmeValidationRequest,
                                                                    AcmeValidationResponse acmeValidationResponse,
                                                                    Instant validationInstant) {
        return DomainValidationEvidence.builder()
                .domain(acmeValidationRequest.getDomain())
                .dcvMethod(acmeValidationRequest.getAcmeType().getDcvMethod())
                .validationDate(validationInstant)
                .mpicDetails(acmeValidationResponse.mpicDetails())
                .dnsType(acmeValidationRequest.getAcmeType().equals(AcmeType.ACME_DNS_01) ? DnsType.TXT : null)
                .dnsRecordName(acmeValidationResponse.dnsRecordName())
                .fileUrl(acmeValidationResponse.fileUrl())
                .randomValue(acmeValidationRequest.getRandomValue())
                .acmeThumbprint(acmeValidationRequest.getAcmeThumbprint())
                .build();
    }

    /**
     * Performs Validation on {@link AcmeValidationRequest} Fields.
     *
     * @param request {@link AcmeValidationRequest} object to validate
     * @throws InputException if the input parameters are invalid. See @{@link InputException} for more details
     */
    private void verifyAcmeValidationRequest(AcmeValidationRequest request) throws DcvException {
        domainNameUtils.validateDomainName(request.getDomain());

        if (request.getAcmeType() == null) {
            throw new InputException(DcvError.ACME_TYPE_REQUIRED);
        }

        if (StringUtils.isEmpty(request.getAcmeThumbprint())) {
            throw new InputException(DcvError.ACME_THUMBPRINT_REQUIRED);
        }

        StateValidationUtils.verifyValidationState(request.getValidationState(), request.getAcmeType().getDcvMethod());
        randomValueVerifier.verifyRandomValue(request.getRandomValue(), request.getValidationState().prepareTime());
    }

    /**
     * Performs Validation on {@link AcmePreparation} Fields.
     *
     * @param acmePreparation {@link AcmePreparation} object to validate
     * @throws InputException if the ACME Preparation fails. See @{@link InputException} for more details
     */
    private void verifyAcmePreparation(AcmePreparation acmePreparation) throws InputException {
        domainNameUtils.validateDomainName(acmePreparation.domain());
    }
}