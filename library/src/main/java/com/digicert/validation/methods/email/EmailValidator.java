package com.digicert.validation.methods.email;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.methods.email.prepare.*;
import com.digicert.validation.methods.email.prepare.provider.*;
import com.digicert.validation.methods.email.validate.EmailValidationRequest;
import com.digicert.validation.random.RandomValueGenerator;
import com.digicert.validation.random.RandomValueVerifier;
import com.digicert.validation.utils.DomainNameUtils;
import com.digicert.validation.utils.StateValidationUtils;
import lombok.Getter;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The EmailValidator class is responsible for preparing and validating email addresses for DCV (Domain Control Validation).
 * This class handles the preparation of email addresses by fetching or constructing them based on the specified
 * email source. It also validates the random values associated with these email addresses to ensure they meet
 * the required entropy and expiration criteria. Sending emails and using emails to validate domain control is
 * beyond the scope of this library.
 * <p>
 * This class implements Validation for the following methods:
 * <ul>
 *     <li>{@link DcvMethod#BR_3_2_2_4_4}</li>
 *     <li>{@link DcvMethod#BR_3_2_2_4_13}</li>
 *     <li>{@link DcvMethod#BR_3_2_2_4_14}</li>
 * </ul>
 *
 */
@Getter
public class EmailValidator {

    /**
     * The DNS TXT provider for email.
     * <p>
     * This provider is responsible for fetching email addresses from DNS TXT records. It is used when the
     * email source is specified as DNS_TXT. The DNS TXT records contain text information associated with a
     * domain, which can include email addresses used for domain validation.
     */
    private EmailProvider emailDnsTxtProvider;

    /**
     * The DNS CAA provider for email.
     * <p>
     * This provider is responsible for fetching email addresses from DNS CAA records. It is used when the
     * email source is specified as DNS_CAA. The DNS CAA records contain record information associated with a
     * domain, which can include email addresses used for domain validation.
     */
    private EmailProvider emailDnsCaaProvider;

    /**
     * The constructed email provider.
     * <p>
     * This provider constructs email addresses based on predefined patterns or rules. It is used when the
     * email source is specified as CONSTRUCTED.
     */
    private EmailProvider emailConstructedProvider;

    /**
     * Utility class for generating random values.
     * <p>
     * This utility is used to generate random strings that are appended to email addresses to ensure
     * uniqueness. The random values are required by the Baseline Requirements (BRs) to be unique for each
     * email address used in domain validation.
     */
    private final RandomValueGenerator randomValueGenerator;

    /**
     * Utility class for random value verification.
     * <p>
     * This utility is used to verify the entropy and expiration of random values associated with email
     * addresses. It ensures that the random values meet the required security standards and have not expired
     * before they are used for domain validation.
     */
    private final RandomValueVerifier randomValueVerifier;

    /**
     * Utility class for domain name operations.
     * <p>
     * This utility provides methods for validating and manipulating domain names. It ensures that domain
     * names are in the correct format and meet the necessary criteria before they are used in email
     * preparation and validation processes.
     */
    private final DomainNameUtils domainNameUtils;

    /**
     * Constructor for EmailValidator.
     * <p>
     * This constructor initializes the EmailValidator with the necessary dependencies and configuration
     * provided by the DcvContext. It sets up the email providers and utility classes required for email
     * preparation and validation.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public EmailValidator(DcvContext dcvContext) {
        emailDnsTxtProvider = dcvContext.get(DnsTxtEmailProvider.class);
        emailDnsCaaProvider = dcvContext.get(DnsCaaEmailProvider.class);
        emailConstructedProvider = new ConstructedEmailProvider();

        randomValueGenerator = dcvContext.get(RandomValueGenerator.class);
        randomValueVerifier = dcvContext.get(RandomValueVerifier.class);
        domainNameUtils = dcvContext.get(DomainNameUtils.class);
    }

    /**
     * Unit Testing Constructor for EmailValidator.
     * <p>
     * This constructor is used for unit testing purposes. It allows the injection of mock or test
     * implementations of the email providers, enabling isolated testing of the EmailValidator class
     * without relying on the actual DcvContext.
     *
     * @param emailDnsTxtProvider The DNS TXT provider
     * @param emailDnsCaaProvider The DNS CAA provider
     * @param emailConstructedProvider The constructed email provider
     */
    EmailValidator(EmailProvider emailDnsTxtProvider,
                   EmailProvider emailDnsCaaProvider,
                   EmailProvider emailConstructedProvider) {
        this(new DcvContext());

        this.emailDnsTxtProvider = emailDnsTxtProvider;
        this.emailDnsCaaProvider = emailDnsCaaProvider;
        this.emailConstructedProvider = emailConstructedProvider;
    }

    /**
     * This will attempt to fetch or build email addresses for the domain based on {@link EmailPreparation#emailSource()}.
     * <p>
     * This method prepares email addresses by fetching them from the specified email source or constructing
     * them based on the email source. It validates the domain name and ensures that each email address
     * has a unique random value as required by the Baseline Requirements (BRs). The prepared email addresses
     * and their associated random values are returned in the EmailPreparationResponse.
     *
     * @param emailPreparation The email preparation request
     * @return The email preparation response
     * @throws DcvException If an error occurs during email preparation
     */
    public EmailPreparationResponse prepare(EmailPreparation emailPreparation) throws DcvException {
        domainNameUtils.validateDomainName(emailPreparation.domain());

        EmailProvider emailProvider = findEmailGenerator(emailPreparation.emailSource());
        EmailDetails emailDetails = emailProvider.findEmailsForDomain(emailPreparation.domain());

        Set<EmailDnsRecordName> emailsDnsRecordNames = emailDetails.emails()
                .stream()
                .filter(e -> DomainNameUtils.isValidEmailAddress(e.email()))
                .collect(Collectors.toSet());


        // The BRs require that each email address have a distinct random value (See for example BR 3.2.2.4.4):
        //      "The Random Value SHALL be unique in each email."
        List<EmailWithRandomValue> emailWithRandomValues = emailsDnsRecordNames.stream()
                .map(email -> new EmailWithRandomValue(email.email(),
                        randomValueGenerator.generateRandomString(),
                        email.dnsRecordName()
                ))
                .toList();

        ValidationState validationState = new ValidationState(emailPreparation.domain(), Instant.now(), emailPreparation.emailSource().getDcvMethod());
        return new EmailPreparationResponse(emailPreparation.domain(),
                emailPreparation.emailSource(),
                emailWithRandomValues,
                validationState,
                emailDetails.mpicDetails());
    }

    /**
     * Performs validation on the values in {@link EmailValidationRequest}. This does not verify
     * validity of email addresses, send emails or acknowledge any email-based interaction by end-users.
     * <p>
     * This method validates the random values associated with email addresses to ensure they meet the
     * required entropy and expiration criteria. It does not verify the validity of the email addresses
     * themselves, nor does it handle sending emails or acknowledging email-based interactions. The method
     * checks the entropy level of the random value and verifies that it has not expired before returning
     * the domain validation evidence.
     *
     * @param request The email validation verification request
     * @return The domain validation evidence
     * @throws DcvException If entropy level is insufficient. If the random value has expired.
     */
    public DomainValidationEvidence validate(EmailValidationRequest request) throws DcvException {
        verifyEmailValidationRequest(request);

        return DomainValidationEvidence.builder()
                .domain(request.getDomain())
                .emailAddress(request.getEmailAddress())
                .randomValue(request.getRandomValue())
                .dcvMethod(request.getEmailSource().getDcvMethod())
                .validationDate(Instant.now())
                .build();
    }

    private void verifyEmailValidationRequest(EmailValidationRequest request) throws DcvException {
        StateValidationUtils.verifyValidationState(request.getValidationState(), request.getEmailSource().getDcvMethod());

        if (!DomainNameUtils.isValidEmailAddress(request.getEmailAddress())) {
            throw new DcvException(DcvError.INVALID_EMAIL_ADDRESS);
        }

        domainNameUtils.validateDomainName(request.getDomain());

        Instant prepareTime = request.getValidationState().prepareTime();
        randomValueVerifier.verifyRandomValue(request.getRandomValue(), prepareTime);
    }

    /**
     * Finds the appropriate email provider based on the email source.
     * <p>
     * This method selects the appropriate email provider based on the specified email source. It uses a
     * switch statement to handle different email sources and returns the corresponding email provider.
     *
     * @param emailSource The email source
     * @return The email provider
     */
    private EmailProvider findEmailGenerator(EmailSource emailSource) {
        // We could use a map here, however the switch provides
        // a default implementation that will throw an exception
        // if a new EmailSource is added and not handled.
        return switch (emailSource) {
            case CONSTRUCTED -> emailConstructedProvider;
            case DNS_TXT -> emailDnsTxtProvider;
            case DNS_CAA -> emailDnsCaaProvider;
        };
    }
}