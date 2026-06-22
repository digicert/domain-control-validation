package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.methods.dns.validate.handlers.PersistentValueHandler;
import com.digicert.validation.repository.DomainsRepository;
import com.digicert.validation.repository.entity.DomainEntity;
import com.digicert.validation.utils.DomainUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatusCode;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DnsPersistentValueMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    @Autowired
    private DomainsRepository domainsRepository;
    @Autowired
    private ObjectMapper objectMapper;
    private final PdnsClient pdnsClient = new PdnsClient();
    private final Long defaultAccountId = 4321L;

    @Test
    void verifyDnsPersistentSubmitFlow_HappyPath() throws JsonProcessingException {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = "https://authority.example/acct/" + System.nanoTime();

        exampleAppClient.submitAccountUri(defaultAccountId, accountUri);

        DcvRequest dcvRequest = new DcvRequest(domainName, null, accountUri, defaultAccountId, DcvRequestType.DNS_TXT_PERSISTENT);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        long persistUntilEpoch = Instant.now().plusSeconds(7200).getEpochSecond();
        String persistentTxtValue = "authority.example; "
                                            + PersistentValueHandler.ACCOUNT_URI_KEY + "=" + accountUri
                                            + "; " + PersistentValueHandler.PERSIST_UNTIL_KEY
                                            + "=" + persistUntilEpoch;

        pdnsClient.addPersistentTxtValue(domainName, persistentTxtValue);

        ValidateRequest validateRequest = ValidateRequest.builder()
                .domain(domainName)
                .dcvRequestType(DcvRequestType.DNS_TXT_PERSISTENT)
                .accountUri(accountUri)
                .build();

        exampleAppClient.validateDomain(validateRequest, createdDomain.getId());

        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
        Optional<DomainEntity> domainEntityQueryResult = domainsRepository.findById(verifiedDomain.getId());
        assertTrue(domainEntityQueryResult.isPresent());
        DomainEntity domainEntity = domainEntityQueryResult.get();
        assertNotNull(domainEntity);
        assertEquals(domainName, domainEntity.getDomainName());
        String validationEvidence = domainEntity.getValidationEvidence();
        assertNotNull(validationEvidence);
        Map<String, Object> domainValidationEvidence = objectMapper.readValue(validationEvidence, Map.class);
        assertNotNull(domainValidationEvidence);
        Map<String, Object> persistentTxtResponse = (Map<String, Object>) domainValidationEvidence.get("persistentTxtResponse");
        assertNotNull(persistentTxtResponse);
        assertEquals(accountUri, persistentTxtResponse.get("accountUri"));
        assertEquals(persistUntilEpoch, ((Number) persistentTxtResponse.get("persistUntil")).longValue());
    }

    @Test
    void verifyDnsPersistentSubmitFlow_AccountOwnershipMismatchFails() {
        String domainName = DomainUtils.getRandomDomainName(2, "net");
        String ownedAccountUri = "https://authority.example/acct/" + System.nanoTime();
        String unownedAccountUri = ownedAccountUri + "-other";

        exampleAppClient.submitAccountUri(defaultAccountId, ownedAccountUri);

        DcvRequest dcvRequest = new DcvRequest(domainName, null, ownedAccountUri, defaultAccountId, DcvRequestType.DNS_TXT_PERSISTENT);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        String persistentTxtValue = "authority.example; "
                                            + PersistentValueHandler.ACCOUNT_URI_KEY + "=" + unownedAccountUri
                                            + "; " + PersistentValueHandler.PERSIST_UNTIL_KEY
                + "=" + Instant.now().plusSeconds(7200).getEpochSecond();

        pdnsClient.addPersistentTxtValue(domainName, persistentTxtValue);

        ValidateRequest validateRequest = ValidateRequest.builder()
                .domain(domainName)
                .dcvRequestType(DcvRequestType.DNS_TXT_PERSISTENT)
                .accountUri(unownedAccountUri)
                .build();

        HttpStatusCode statusCode = exampleAppClient.validateDomainExpectingFailure(validateRequest, createdDomain.getId());
        assertTrue(statusCode.is4xxClientError());
    }
}
