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
class FileMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    @Autowired
    private PdnsClient pdnsClient;

    private final Long defaultAccountId = 1234L;

    @Test
    void verifyFileAuth_happyDayFlow() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_AUTH);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent("fileauth.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "fileauth.txt"), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileAuth_happyDayFlow_CustomFilename() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), "customfilename", defaultAccountId, DcvRequestType.FILE_AUTH);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent("customfilename.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "customfilename.txt"), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileAuth_useDifferentValueAsFileName() throws IOException {
        String fileName = "some-file.txt";

        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_AUTH);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent(fileName, createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, fileName), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileAuth_useDefaultFilename() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_AUTH);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent("fileauth.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, null), createdDomain.getId());

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

    private static ValidateRequest createValidateRequest(DomainResource createdDomain, String file) {
        return ValidateRequest.builder()
                .dcvRequestType(DcvRequestType.FILE_AUTH)
                .filename(file)
                .randomValue(createdDomain.getRandomValueDetails().getFirst().getRandomValue())
                .domain(createdDomain.getDomainName())
                .build();
    }
}
