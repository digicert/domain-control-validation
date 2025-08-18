package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.utils.DomainUtils;
import com.digicert.validation.utils.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AcmeHttpMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    @Autowired
    private PdnsClient pdnsClient;

    private final Long defaultAccountId = 1234L;

    @Test
    void verifyAcmeHTTP_happyDayFlow() throws IOException {
        // Set the acme thumbprint ... just re-use the account token key
        String hashingKey = "acme-thumbprint-key";
        exampleAppClient.submitAccountTokenKey(defaultAccountId, hashingKey);

        String domainName = DomainUtils.getRandomDomainName(2, "com");
        DcvRequest dcvRequest = createDcvRequest(domainName, DcvRequestType.ACME_HTTP);

        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);
        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(domainName);
        // Write random value to file
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        FileUtils.writeAcmeHttpFileWithContent(randomValue, randomValue + "." + hashingKey);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.ACME_HTTP);
        exampleAppClient.validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
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
