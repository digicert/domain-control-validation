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
class DnsTokenValueMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    private final PdnsClient pdnsClient = new PdnsClient();
    private final Long defaultAccountId = 1234L;
    private final CSRGenerator csrGenerator = new CSRGenerator();

    @Test
    void verifyDnsTokenTxt_HappyPath() throws Exception {
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

        DcvRequest dcvRequest = createDcvRequest(domainName);
        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        pdnsClient.addRandomValueToRecord(domainName, dnsTxtTokenValue, PdnsClient.PdnsRecordType.TXT);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(dcvRequest.domain(), hashingValue);
        exampleAppClient.validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    private DcvRequest createDcvRequest(String domainName) {
        return new DcvRequest(domainName, defaultAccountId, DcvRequestType.DNS_TXT_TOKEN);
    }

    private static ValidateRequest getValidateRequest(String domain,
                                                      String tokenValue) {
        return ValidateRequest.builder()
                .dcvRequestType(DcvRequestType.DNS_TXT_TOKEN)
                .domain(domain)
                .tokenValue(tokenValue)
                .build();
    }

    private DomainResource submitDnsDomain(DcvRequest dcvRequest) {
        return exampleAppClient.submitDnsDomain(dcvRequest);
    }

    private DomainResource getDomainResource(long domainId) {
        return exampleAppClient.getDomainResource(domainId);
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
