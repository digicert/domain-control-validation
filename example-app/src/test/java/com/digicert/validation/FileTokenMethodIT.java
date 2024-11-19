package com.digicert.validation;

import com.digicert.validation.challenges.BasicRequestTokenData;
import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.challenges.BasicRequestTokenUtils;
import com.digicert.validation.utils.CSRGenerator;
import com.digicert.validation.utils.DomainUtils;
import com.digicert.validation.utils.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class FileTokenMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    private final PdnsClient pdnsClient = new PdnsClient();
    private final Long defaultAccountId = 1234L;
    private final CSRGenerator csrGenerator = new CSRGenerator();

    @Test
    void verifyFileToken_happyDayFlow() throws Exception {
        String domainName = DomainUtils.getRandomDomainName(2, "com");

        String hashingKey = "token-key";
        // Set the token key for the account
        exampleAppClient.submitAccountTokenKey(defaultAccountId, hashingKey);

        String hashingValue = csrGenerator.generateCSR(domainName);
        ZonedDateTime zonedDateTime = Instant.now().atZone(ZoneId.of("UTC"));
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
        String formattedDate = zonedDateTime.format(formatter);

        BasicRequestTokenUtils basicRequestTokenUtils = new BasicRequestTokenUtils();
        String dnsTxtTokenValue = basicRequestTokenUtils.generateRequestToken(new BasicRequestTokenData(hashingKey, hashingValue), formattedDate).orElseThrow();

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(domainName);
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent("fileauth.txt", dnsTxtTokenValue);

        DcvRequest dcvRequest = new DcvRequest(domainName, defaultAccountId, DcvRequestType.FILE_VALIDATION_TOKEN);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(dcvRequest, createdDomain);

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "fileauth.txt", hashingValue), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileToken_happyDayFlow_customFilename() throws Exception {
        String domainName = DomainUtils.getRandomDomainName(2, "com");

        String hashingKey = "token-key";
        // Set the token key for the account
        exampleAppClient.submitAccountTokenKey(defaultAccountId, hashingKey);

        String hashingValue = csrGenerator.generateCSR(domainName);
        ZonedDateTime zonedDateTime = Instant.now().atZone(ZoneId.of("UTC"));
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
        String formattedDate = zonedDateTime.format(formatter);

        BasicRequestTokenUtils basicRequestTokenUtils = new BasicRequestTokenUtils();
        String dnsTxtTokenValue = basicRequestTokenUtils.generateRequestToken(new BasicRequestTokenData(hashingKey, hashingValue), formattedDate).orElseThrow();

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(domainName);
        // Write random value to file
        FileUtils.writeNginxStaticFileWithContent("customlocation.txt", dnsTxtTokenValue);

        DcvRequest dcvRequest = new DcvRequest(domainName, "customlocation", defaultAccountId, DcvRequestType.FILE_VALIDATION_TOKEN);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(dcvRequest, createdDomain);

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "customlocation.txt", hashingValue), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    private static ValidateRequest createValidateRequest(DomainResource createdDomain, String file, String tokenValue) {
        return ValidateRequest.builder()
                .dcvRequestType(DcvRequestType.FILE_VALIDATION_TOKEN)
                .filename(file)
                .tokenValue(tokenValue)
                .randomValue(createdDomain.getRandomValueDetails().getFirst().getRandomValue())
                .domain(createdDomain.getDomainName())
                .build();
    }

    private void assertCreatedDomain(DcvRequest dcvRequest, DomainResource createdDomain) {
        assertNotNull(createdDomain);
        assertNotEquals(0, createdDomain.getId());
        assertEquals(dcvRequest.domain(), createdDomain.getDomainName());
        assertEquals(dcvRequest.accountId(), createdDomain.getAccountId());
        assertEquals(dcvRequest.dcvRequestType(), createdDomain.getDcvType());
        assertEquals(DcvRequestStatus.PENDING, createdDomain.getStatus());
    }
}
