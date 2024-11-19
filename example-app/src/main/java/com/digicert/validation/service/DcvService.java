package com.digicert.validation.service;

import java.util.List;
import java.util.Objects;

import org.springframework.stereotype.Component;

import com.digicert.validation.DcvManager;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.exceptions.DcvBaseException;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.DomainNotFoundException;
import com.digicert.validation.exceptions.EmailFailedException;
import com.digicert.validation.exceptions.InvalidDcvRequestException;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.exceptions.ValidationFailedException;
import com.digicert.validation.exceptions.ValidationStateParsingException;
import com.digicert.validation.methods.dns.prepare.DnsPreparation;
import com.digicert.validation.methods.dns.prepare.DnsPreparationResponse;
import com.digicert.validation.methods.dns.validate.DnsValidationRequest;
import com.digicert.validation.methods.email.prepare.EmailPreparation;
import com.digicert.validation.methods.email.prepare.EmailPreparationResponse;
import com.digicert.validation.methods.email.prepare.EmailSource;
import com.digicert.validation.methods.email.validate.EmailValidationRequest;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationRequest;
import com.digicert.validation.methods.fileauth.prepare.FileAuthPreparationResponse;
import com.digicert.validation.methods.fileauth.validate.FileAuthValidationRequest;
import com.digicert.validation.repository.AccountsRepository;
import com.digicert.validation.repository.DomainsRepository;
import com.digicert.validation.repository.entity.AccountsEntity;
import com.digicert.validation.repository.entity.DomainEntity;
import com.digicert.validation.repository.entity.DomainRandomValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class DcvService {
    private final DcvManager dcvManager;
    private final DomainsRepository domainsRepository;
    private final AccountsRepository accountsRepository;
    private final ObjectMapper objectMapper;


    public DcvService(DcvManager dcvManager, DomainsRepository domainsRepository, AccountsRepository accountsRepository,
                      ObjectMapper objectMapper) {
        this.dcvManager = dcvManager;
        this.domainsRepository = domainsRepository;
        this.accountsRepository = accountsRepository;
        this.objectMapper = objectMapper;
    }

    public DomainResource submitDomain(DcvRequest dcvRequest) throws DcvBaseException {
        DomainEntity createdEntity = null;

        try {
            switch (dcvRequest.dcvRequestType()) {
                case DNS_TXT, DNS_CNAME, DNS_TXT_TOKEN -> createdEntity = submitDnsDomain(dcvRequest);
                case EMAIL_CONSTRUCTED, EMAIL_WHOIS, EMAIL_DNS_TXT -> createdEntity = submitEmailDomain(dcvRequest);
                case FILE_AUTH, FILE_AUTH_TOKEN -> createdEntity = submitFileDomain(dcvRequest);
            }
        } catch(DcvException ex){
            log.info("Failed submitting domain", ex);
            throw new ValidationFailedException("Error submitting domain for validation" );
        }

        return new DomainResource(createdEntity);
    }

    public void validateDomain(Long domainId, ValidateRequest validateRequest) throws DcvBaseException {
        DomainEntity domainEntity = getDomainEntity(domainId);
        validateDomainMatchesRequest(domainEntity, validateRequest);
        ValidationState validationState = getValidationState(domainEntity);
        long accountId = domainEntity.getAccountId();

        switch (validateRequest.dcvRequestType) {
            case DNS_TXT, DNS_CNAME, DNS_TXT_TOKEN -> validateDnsDomain(accountId, validationState, validateRequest);
            case EMAIL_CONSTRUCTED, EMAIL_WHOIS, EMAIL_DNS_TXT ->
                    validateEmailDomain(validationState, validateRequest);
            case FILE_AUTH, FILE_AUTH_TOKEN -> validateFileDomain(accountId, validationState, validateRequest);
        }

        domainEntity.status = DcvRequestStatus.VALID.name();
        domainsRepository.save(domainEntity);
    }

    public DomainEntity getDomainEntity(Long domainId) throws DcvBaseException{
        return domainsRepository
                .findById(domainId)
                .orElseThrow(() -> new DomainNotFoundException("DomainEntity not found"));
    }

    private DomainEntity saveDnsValidationState(DcvRequest request, DnsPreparationResponse prepare) throws DcvBaseException {
        DomainEntity domainEntity = new DomainEntity(request);
        if (prepare.getRandomValue() != null) {
            DomainRandomValue randomValue = new DomainRandomValue(prepare.getRandomValue(), null, domainEntity);
            randomValue.domain = domainEntity;
            domainEntity.setDomainRandomValues(List.of(randomValue));
        }

        return saveValidationState(domainEntity, prepare.getValidationState());
    }

    private DomainEntity saveEmailValidationState(DcvRequest request, EmailPreparationResponse prepare) throws DcvBaseException {
        DomainEntity domainEntity = new DomainEntity(request);

        List<DomainRandomValue> randomValues = prepare.emailWithRandomValue().stream()
                .map(emailWithRandomValue -> new DomainRandomValue(emailWithRandomValue.randomValue(), emailWithRandomValue.email(), domainEntity))
                .toList();
        domainEntity.setDomainRandomValues(randomValues);

        return saveValidationState(domainEntity, prepare.validationState());
    }

    private DomainEntity saveFileValidationState(DcvRequest request, FileAuthPreparationResponse prepare) throws DcvBaseException {
        DomainEntity domainEntity = new DomainEntity(request);
        DomainRandomValue randomValue = new DomainRandomValue(prepare.getRandomValue(), null, domainEntity);
        domainEntity.setDomainRandomValues(List.of(randomValue));

        return saveValidationState(domainEntity, prepare.getValidationState());
    }

    private DomainEntity saveValidationState(DomainEntity domainEntity, ValidationState validationState) throws DcvBaseException {
        try {
            domainEntity.validationState = objectMapper.writeValueAsString(validationState);
        } catch (JsonProcessingException e) {
            log.error("Error parsing validation state", e);
            throw new ValidationStateParsingException("Error parsing validation state returned from dcv library");
        }

        return domainsRepository.save(domainEntity);
    }

    private DomainEntity submitDnsDomain(DcvRequest dcvRequest) throws DcvBaseException {
        DnsType dnsType = mapToDnsType(dcvRequest.dcvRequestType());
        DnsPreparation dnsPreparation = new DnsPreparation(dcvRequest.domain(), dnsType, mapToChallengeType(dcvRequest.dcvRequestType()));

        try {
            DnsPreparationResponse prepare = dcvManager.getDnsValidator().prepare(dnsPreparation);

            // Save the validation state to the database
            return saveDnsValidationState(dcvRequest, prepare);
        } catch(DcvException e) {
            log.warn("Error preparing DNS validation", e);
            throw new ValidationFailedException("Error preparing DNS validation");
        }
    }

    private DomainEntity submitEmailDomain(DcvRequest dcvRequest) throws DcvBaseException, DcvException {
        EmailSource emailSource = mapToEmailSource(dcvRequest.dcvRequestType());
        EmailPreparation emailPreparation = new EmailPreparation(dcvRequest.domain(), emailSource);

        EmailPreparationResponse preparationResponse;
        try {
            preparationResponse = dcvManager.getEmailValidator().prepare(emailPreparation);
        } catch(PreparationException e) {
            log.warn("Error preparing email validation. exception_message={}", e.getMessage());
            throw new EmailFailedException("Error preparing email validation");
        }

        if (preparationResponse.emailWithRandomValue().isEmpty()) {
            throw new EmailFailedException("No usable email addresses found");
        }

        // Send the email
        log.info("Email sent to: {}", preparationResponse.emailWithRandomValue());

        // Save the validation state to the database
        return saveEmailValidationState(dcvRequest, preparationResponse);
    }

    private DomainEntity submitFileDomain(DcvRequest dcvRequest) throws DcvBaseException {
        FileAuthPreparationRequest dnsPreparation = new FileAuthPreparationRequest(dcvRequest.domain(), dcvRequest.filename(),
                mapToChallengeType(dcvRequest.dcvRequestType()));
        FileAuthPreparationResponse prepare;

        try {
            prepare = dcvManager.getFileAuthValidator().prepare(dnsPreparation);
        } catch (DcvException e) {
            throw new ValidationFailedException("Error preparing file validation");
        }
        // Save the validation state to the database
        return saveFileValidationState(dcvRequest, prepare);
    }


    private void validateDomainMatchesRequest(DomainEntity domainEntity, ValidateRequest validateRequest)
            throws DcvBaseException {

        if (!Objects.equals(domainEntity.domainName, validateRequest.domain)) {
            throw new InvalidDcvRequestException("Domain data does not match submitted validation request");
        }
        if (!Objects.equals(domainEntity.dcvType, validateRequest.dcvRequestType.toString())) {
            throw new InvalidDcvRequestException("Supplied dcvRequestType does not match domain");
        }
        if (!domainEntity.status.equals(DcvRequestStatus.PENDING.name())) {
            throw new InvalidDcvRequestException("Domain is not pending validation");
        }

        // Validate the random values
        switch (validateRequest.dcvRequestType) {
            case DNS_TXT, DNS_CNAME -> {
                if (domainEntity.domainRandomValues.stream().noneMatch(randomValue -> randomValue.randomValue.equals(validateRequest.randomValue))) {
                    throw new InvalidDcvRequestException("Supplied random value is invalid for domain");
                }
            }
            case EMAIL_CONSTRUCTED, EMAIL_WHOIS, EMAIL_DNS_TXT -> {
                if (domainEntity.domainRandomValues.stream().noneMatch(randomValue ->
                        randomValue.randomValue.equals(validateRequest.randomValue) && randomValue.email.equals(validateRequest.emailAddress))) {
                    throw new InvalidDcvRequestException("Supplied email, random value pair are invalid for domain");
                }
            }
            case DNS_TXT_TOKEN, FILE_AUTH -> {} // No random value to check
        }
    }

    private ValidationState getValidationState(DomainEntity domainEntity) throws DcvBaseException {
        try {
            return objectMapper.readValue(domainEntity.validationState, ValidationState.class);
        } catch (JsonProcessingException e) {
            log.error("Error parsing validation state", e);
            throw new ValidationStateParsingException("Error parsing validation state for domain");
        }
    }

    private void validateDnsDomain(long accountId, ValidationState validationState, ValidateRequest validateRequest)
            throws DcvBaseException {

        DnsType dnsType = mapToDnsType(validateRequest.dcvRequestType);
        DnsValidationRequest.DnsValidationRequestBuilder requestBuilder = DnsValidationRequest.builder()
                .domain(validateRequest.domain)
                .randomValue(validateRequest.randomValue)
                .tokenValue(validateRequest.tokenValue)
                .dnsType(dnsType)
                .challengeType(mapToChallengeType(validateRequest.dcvRequestType))
                .validationState(validationState);

        // Set the token key if it is a DNS_TXT_TOKEN request
        if (validateRequest.dcvRequestType == DcvRequestType.DNS_TXT_TOKEN) {
            accountsRepository.findById(accountId).ifPresent(accountsEntity -> requestBuilder.tokenKey(accountsEntity.tokenKey));
        }

        DnsValidationRequest dnsValidationRequest = requestBuilder.build();

        try {
            dcvManager.getDnsValidator().validate(dnsValidationRequest);
        } catch (DcvException e) {
            throw new ValidationFailedException(e.getMessage());
        }
    }

    private static ChallengeType mapToChallengeType(DcvRequestType dcvRequestType) {
        return switch (dcvRequestType) {
            case FILE_AUTH, DNS_TXT, DNS_CNAME -> ChallengeType.RANDOM_VALUE;
            case FILE_AUTH_TOKEN, DNS_TXT_TOKEN -> ChallengeType.REQUEST_TOKEN;
            default -> throw new IllegalStateException("Unexpected value: " + dcvRequestType);
        };
    }

    private void validateEmailDomain(ValidationState validationState, ValidateRequest validateRequest) throws DcvBaseException {
        EmailSource emailSource = mapToEmailSource(validateRequest.dcvRequestType);
        EmailValidationRequest emailVerification = EmailValidationRequest.builder()
                .domain(validateRequest.domain)
                .emailSource(emailSource)
                .emailAddress(validateRequest.emailAddress)
                .randomValue(validateRequest.randomValue)
                .validationState(validationState)
                .build();

        try {
            dcvManager.getEmailValidator().validate(emailVerification);
        } catch(DcvException e) {
            log.warn("Failed validating email", e);
            throw new ValidationFailedException(e.getMessage());
        }
    }

    private void validateFileDomain(Long accountId, ValidationState validationState, ValidateRequest validateRequest)
            throws DcvBaseException {

        FileAuthValidationRequest.FileAuthValidationRequestBuilder requestBuilder = FileAuthValidationRequest.builder()
                .domain(validateRequest.domain)
                .randomValue(validateRequest.randomValue)
                .filename(validateRequest.filename)
                .tokenValue(validateRequest.tokenValue)
                .challengeType(mapToChallengeType(validateRequest.dcvRequestType))
                .validationState(validationState);

        // Set the token key if it is a FILE_AUTH_TOKEN request
        if (validateRequest.dcvRequestType == DcvRequestType.FILE_AUTH_TOKEN) {
            accountsRepository.findById(accountId).ifPresent(accountsEntity -> requestBuilder.tokenKey(accountsEntity.tokenKey));
        }

        try {
            dcvManager.getFileAuthValidator().validate(requestBuilder.build());
        } catch (DcvException e) {
            throw new ValidationFailedException(e.getMessage());
        }
    }

    private EmailSource mapToEmailSource(DcvRequestType dcvRequestType) throws DcvBaseException {
        return switch (dcvRequestType) {
            case EMAIL_CONSTRUCTED -> EmailSource.CONSTRUCTED;
            case EMAIL_WHOIS -> EmailSource.WHOIS;
            case EMAIL_DNS_TXT -> EmailSource.DNS_TXT;
            default -> throw new InvalidDcvRequestException("Invalid dcvRequestType, must be one of the following"
                    + List.of(DcvRequestType.values()));
        };
    }

    private DnsType mapToDnsType(DcvRequestType dcvRequestType) throws DcvBaseException {
        return switch (dcvRequestType) {
            case DNS_TXT, DNS_TXT_TOKEN -> DnsType.TXT;
            case DNS_CNAME -> DnsType.CNAME;
            default -> throw new InvalidDcvRequestException("Invalid dcvRequestType, must be one of the following"
                    + List.of(DcvRequestType.values()));
        };
    }

    public void createTokenForAccount(long accountId, String tokenKey) {
        accountsRepository.save(new AccountsEntity(accountId, tokenKey));
    }
}
