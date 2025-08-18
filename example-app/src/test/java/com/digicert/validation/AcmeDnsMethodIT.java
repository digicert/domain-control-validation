package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.utils.DomainUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AcmeDnsMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    @Autowired
    private PdnsClient pdnsClient;

    private final Long defaultAccountId = 1234L;

    @Test
    void verifyAcmeDNS_happyDayFlow() {
        // Set the acme thumbprint ... just re-use the account token key
        String hashingKey = "acme-thumbprint-key";
        exampleAppClient.submitAccountTokenKey(defaultAccountId, hashingKey);

        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.ACME_DNS);

        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);
        assertCreatedDomain(createdDomain, dcvRequest);

        // Create PDNS DNS Text Entry for the domain
        // ACME DNS validation requires a TXT record that is a hashed value of "<randomValue>.<hashkey>"
        // and then placed under the "_acme-challenge" subdomain.
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        String dnsTxtValue = computeDnsTxtValue(randomValue + "." + hashingKey);
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), List.of(dnsTxtValue), PdnsClient.PdnsRecordType.TXT, "_acme-challenge");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.ACME_DNS);
        exampleAppClient.validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyAcmeDNS_happyDayFlow_multipleTxtEntries() {
        // Set the acme thumbprint ... just re-use the account token key
        String hashingKey = "acme-thumbprint-key";
        exampleAppClient.submitAccountTokenKey(defaultAccountId, hashingKey);

        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.ACME_DNS);

        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);
        assertCreatedDomain(createdDomain, dcvRequest);

        // Create PDNS DNS Text Entry for the domain
        // ACME DNS validation requires a TXT record that is a hashed value of "<randomValue>.<hashkey>"
        // and then placed under the "_acme-challenge" subdomain.
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        String dnsTxtValue = computeDnsTxtValue(randomValue + "." + hashingKey);
        List<String> dnsValues = List.of(dnsTxtValue, "some-other-value", "another-value");
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), dnsValues, PdnsClient.PdnsRecordType.TXT, "_acme-challenge");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.ACME_DNS);
        exampleAppClient.validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @SneakyThrows
    private String computeDnsTxtValue(String keyAuthorization) {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(keyAuthorization.getBytes());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(messageDigest.digest());
    }


    private static void assertCreatedDomain(DomainResource createdDomain, DcvRequest dcvRequest) {
        assertNotNull(createdDomain);
        assertNotEquals(0, createdDomain.getId());
        assertEquals(dcvRequest.domain(), createdDomain.getDomainName());
        assertEquals(dcvRequest.accountId(), createdDomain.getAccountId());
        assertEquals(dcvRequest.dcvRequestType(), createdDomain.getDcvType());
        assertEquals(DcvRequestStatus.PENDING, createdDomain.getStatus());
        assertEquals(1, createdDomain.getRandomValueDetails().size());
        createdDomain.getRandomValueDetails().forEach(domainRandomValueResource -> {
            assertNotNull(domainRandomValueResource.getRandomValue());
            assertNull(domainRandomValueResource.getEmail());
        });
    }

    private DcvRequest createDcvRequest(String domainName, DcvRequestType dcvRequestType) {
        return new DcvRequest(domainName, defaultAccountId, dcvRequestType);
    }

    private static ValidateRequest getValidateRequest(DomainResource createdDomain, DcvRequestType dcvRequestType) {
        return ValidateRequest.builder()
                .dcvRequestType(dcvRequestType)
                .randomValue(createdDomain.getRandomValueDetails().getFirst().getRandomValue())
                .domain(createdDomain.getDomainName())
                .build();
    }

}
