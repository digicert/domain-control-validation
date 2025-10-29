package com.digicert.validation.methods.dns;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.*;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.dns.prepare.DnsPreparation;
import com.digicert.validation.methods.dns.prepare.DnsPreparationResponse;
import com.digicert.validation.methods.dns.validate.DnsValidationHandler;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.dns.validate.DnsValidationResponse;
import com.digicert.validation.random.RandomValueGenerator;
import com.digicert.validation.random.RandomValueVerifier;
import com.digicert.validation.utils.DomainNameUtils;
import com.digicert.validation.utils.StateValidationUtils;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;

import java.time.Instant;
import java.util.List;

/**
 * DnsValidator is a class that provides methods to prepare and validate DNS records for domain validation.
 * <p>
 * This class implements Validation for the following methods:
 * <ul>
 *    <li>{@link DcvMethod#BR_3_2_2_4_7}</li>
 * </ul>
 * <p>
 * The DnsValidator class is responsible for handling the preparation and validation of DNS records as part of the domain control validation process.
 * It utilizes various utility classes and handlers to generate random values, verify domain names, and validate DNS records.
 * The class ensures that the DNS records are correctly prepared and validated according to the specified DNS type and challenge type.
 */
@Slf4j
public class DnsValidator {

    /** Utility class for generating random values */
    private final RandomValueGenerator randomValueGenerator;

    /** Handler for DNS Validation */
    private final DnsValidationHandler dnsValidationHandler;

    /** Utility class for random value verification */
    private final RandomValueVerifier randomValueVerifier;

    /** Utility class for domain name operations */
    private final DomainNameUtils domainNameUtils;

    /** List of allowed DNS Types for DNS Validation */
    private final List<DnsType> allowedDnsTypes = List.of(DnsType.CNAME, DnsType.TXT, DnsType.CAA);

    /** The log level used for logging errors related to domain control validation (DCV). */
    private final Level logLevelForDcvErrors;

    /**
     * Constructor for DnsValidator
     * <p>
     * This constructor initializes the DnsValidator class with the necessary dependencies and configuration.
     * It retrieves the required instances from the provided DcvContext and sets up the utility classes and handlers for DNS validation.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public DnsValidator(DcvContext dcvContext) {
        this.randomValueGenerator = dcvContext.get(RandomValueGenerator.class);
        this.dnsValidationHandler = dcvContext.get(DnsValidationHandler.class);
        this.randomValueVerifier = dcvContext.get(RandomValueVerifier.class);
        this.domainNameUtils = dcvContext.get(DomainNameUtils.class);
        logLevelForDcvErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();
    }

    /**
     * Prepare the DNS record for validation
     * <p>
     * This method prepares the DNS record for validation by generating the necessary random values and setting up the validation state.
     * It verifies the DNS preparation parameters and constructs a DnsPreparationResponse object containing the random value and allowed FQDNs.
     *
     * @param dnsPreparation {@link DnsPreparation} object containing the domain, DNS Type and Challenge Type
     * @return {@link DnsPreparationResponse} object containing the random value and allowed FQDNs
     * @throws DcvException if the DNS Preparation fails.
     */
    public DnsPreparationResponse prepare(DnsPreparation dnsPreparation) throws DcvException {
        log.debug("dnsPreparation={}", dnsPreparation);

        verifyDnsPreparation(dnsPreparation);

        DnsPreparationResponse.DnsPreparationResponseBuilder dnsPreparationResponseBuilder = DnsPreparationResponse.builder()
                .dnsType(dnsPreparation.dnsType())
                .domain(dnsPreparation.domain())
                .allowedFqdns(domainNameUtils.getDomainAndParents(dnsPreparation.domain()))
                .validationState(new ValidationState(dnsPreparation.domain(), Instant.now(), DcvMethod.BR_3_2_2_4_7));

        if (dnsPreparation.challengeType() == ChallengeType.RANDOM_VALUE) {
            dnsPreparationResponseBuilder.randomValue(randomValueGenerator.generateRandomString());
        }

        DnsPreparationResponse dnsPreparationResponse = dnsPreparationResponseBuilder.build();
        log.debug("dnsPreparationResponse={}", dnsPreparationResponse);
        return dnsPreparationResponse;
    }

    /**
     * Validate the DNS record for domain validation
     * <p>
     * This method validates the DNS record for domain validation by interacting with the DNS server and verifying the DNS records.
     * It checks the validity of the DNS validation request and constructs a DomainValidationEvidence object if the validation is successful.
     *
     * @param dnsValidationRequest {@link DnsValidationRequest} object containing the domain, DNS Type, Challenge Type and Validation State
     * @return {@link DomainValidationEvidence} object containing the domain validation evidence
     * @throws ValidationException if the DNS Validation fails.
     * @throws InputException      if the input parameters are invalid.
     * <p>
     * See @{@link ValidationException} for more details
     */
    public DomainValidationEvidence validate(DnsValidationRequest dnsValidationRequest) throws DcvException {
        log.debug("dnsValidationRequest={}", dnsValidationRequest);

        verifyDnsValidationRequest(dnsValidationRequest);

        DnsValidationResponse dnsValidationResponse = dnsValidationHandler.validate(dnsValidationRequest);

        if (dnsValidationResponse.isValid()) {
            // Set the timestamp of when the validation was completed
            // This time should be within a few ms of the validation succeeding
            Instant validationInstant = Instant.now();

            log.info("event_id={} domain={}", LogEvents.DNS_VALIDATION_SUCCESSFUL, dnsValidationRequest.getDomain());
            return createDomainValidationEvidence(dnsValidationRequest, dnsValidationResponse, validationInstant);
        } else {
            log.atLevel(logLevelForDcvErrors).log(
                    "event_id={} domain={} mpic_details={} dnsType={} errors={}",
                    LogEvents.DNS_VALIDATION_FAILED,
                    dnsValidationRequest.getDomain(),
                    dnsValidationResponse.mpicDetails(),
                    dnsValidationRequest.getDnsType().toString(),
                    dnsValidationResponse.errors());

            throw new ValidationException(dnsValidationResponse.errors());
        }
    }

    /**
     * Creates a DomainValidationEvidence object from the DnsValidationRequest and DnsValidationResponse
     *
     * @param dnsValidationRequest  The DnsValidationRequest object containing the domain, DNS Type, challenge type, and Validation State used
     * @param dnsValidationResponse The DnsValidationResponse object containing the server, domain, and random value or request token used
     * @param validationInstant     The Instant when the validation was completed
     * @return DomainValidationEvidence object containing the domain validation evidence
     */
    private DomainValidationEvidence createDomainValidationEvidence(DnsValidationRequest dnsValidationRequest,
                                                                    DnsValidationResponse dnsValidationResponse,
                                                                    Instant validationInstant) {
        return DomainValidationEvidence.builder()
                .domain(dnsValidationRequest.getDomain())
                .dcvMethod(dnsValidationRequest.getValidationState().dcvMethod())
                .validationDate(validationInstant)
                // DNS Specific Values
                .mpicDetails(dnsValidationResponse.mpicDetails())
                .dnsType(dnsValidationRequest.getDnsType())
                .dnsRecordName(dnsValidationResponse.dnsRecordName())
                .randomValue(dnsValidationResponse.validRandomValue())
                .requestToken(dnsValidationResponse.validRequestToken())
                .build();
    }

    /**
     * Performs Validation on {@link DnsValidationRequest} Fields.
     *
     * @param request {@link DnsValidationRequest} object to validate
     * @throws InputException if the input parameters are invalid. See @{@link InputException} for more details
     */
    private void verifyDnsValidationRequest(DnsValidationRequest request) throws DcvException {
        domainNameUtils.validateDomainName(request.getDomain());

        if (request.getDnsType() == null) {
            throw new InputException(DcvError.DNS_TYPE_REQUIRED);
        }

        if (!allowedDnsTypes.contains(request.getDnsType())) {
            throw new InputException(DcvError.INVALID_DNS_TYPE);
        }

        if (request.getChallengeType() == null) {
            throw new InputException(DcvError.CHALLENGE_TYPE_REQUIRED);
        }

        String domainLabel = request.getDomainLabel();
        if (domainLabel != null && !domainLabel.isEmpty()) {
            // Invalid if:
            // 1. Does not start with underscore
            // 2. Contains any '.' character that is not the final character
            boolean containsInvalidDot = domainLabel.substring(0, domainLabel.length() - 1).contains(".");
            if (!domainLabel.startsWith("_") || containsInvalidDot) {
                throw new InputException(DcvError.DNS_DOMAIN_LABEL_INVALID);
            }
        }

        StateValidationUtils.verifyValidationState(request.getValidationState(), DcvMethod.BR_3_2_2_4_7);

        switch (request.getChallengeType()) {
            case RANDOM_VALUE -> {
                Instant instant = request.getValidationState().prepareTime();
                randomValueVerifier.verifyRandomValue(request.getRandomValue(), instant);
            }
            case REQUEST_TOKEN -> {
                if (request.getRequestTokenData() == null) {
                    throw new InputException(DcvError.REQUEST_TOKEN_DATA_REQUIRED);
                }
            }
        }
    }

    /**
     * Performs Validation on {@link DnsPreparation} Fields.
     *
     * @param dnsPreparation {@link DnsPreparation} object to validate
     * @throws InputException if the DNS Preparation fails. See @{@link InputException} for more details
     */
    private void verifyDnsPreparation(DnsPreparation dnsPreparation) throws InputException {
        domainNameUtils.validateDomainName(dnsPreparation.domain());

        if (dnsPreparation.dnsType() == null) {
            throw new InputException(DcvError.DNS_TYPE_REQUIRED);
        }

        if (dnsPreparation.challengeType() == null) {
            throw new InputException(DcvError.CHALLENGE_TYPE_REQUIRED);
        }

        if (!allowedDnsTypes.contains(dnsPreparation.dnsType())) {
            throw new InputException(DcvError.INVALID_DNS_TYPE);
        }

    }
}