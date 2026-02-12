package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainRandomValueDetails;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.DcvManager;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.utils.DomainUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DnsRandomValueMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    
    @Autowired
    private DcvManager dcvManager;
    
    private final PdnsClient pdnsClient = new PdnsClient();
    private final Long defaultAccountId = 1234L;

    @Test
    void verifyDnsTxtSubmitFlow_HappyPath() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), randomValue, PdnsClient.PdnsRecordType.TXT);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
        
        // Verify DcvManager.getLookupLocations() for DNS TXT method
        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_7);
        assertNotNull(lookupLocations, "DNS TXT lookup locations should not be null");
        assertFalse(lookupLocations.isEmpty(), "DNS TXT lookup locations should not be empty");
        assertTrue(lookupLocations.stream().anyMatch(url -> url.contains(dcvRequest.domain())), 
                   "Lookup locations should contain domain: " + dcvRequest.domain());
    }

    @Test
    void verifyDnsTxtSubmitFlow_withNoDomainLabel() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), List.of(randomValue), PdnsClient.PdnsRecordType.TXT, "");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsTxtSubmitFlow_withDomainLabelAndRootDomain() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), List.of("some-other-value"), PdnsClient.PdnsRecordType.TXT, "_dnsauth");
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), List.of(randomValue), PdnsClient.PdnsRecordType.TXT, "");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsTxtSubmitFlow_withExtraCharsInTxtEntry() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), "some-wierd-text " + randomValue + " more text", PdnsClient.PdnsRecordType.TXT);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsTxtSubmitFlow_withSubDomains() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(4, "org"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), randomValue, PdnsClient.PdnsRecordType.TXT);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsTxtSubmitFlow_subDomain_NoNamePrefix() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(4, "net"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), List.of(randomValue), PdnsClient.PdnsRecordType.TXT, "");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsTxtSubmitFlow_multipleTxtEntries() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(3, "com"), DcvRequestType.DNS_TXT);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS DNS Text Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        List<String> dnsValues = List.of(randomValue, "some-other-value", "another-value");
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), dnsValues, PdnsClient.PdnsRecordType.TXT, "");

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_TXT);
        validateDomain(validateRequest, createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsCnameSubmitFlow_HappyPath() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.DNS_CNAME);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS CNAME Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), randomValue, PdnsClient.PdnsRecordType.CNAME);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_CNAME);
        validateDomain(validateRequest, createdDomain.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyDnsCnameSubmitFlow_withSubDomain() {
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(5, "net"), DcvRequestType.DNS_CNAME);

        DomainResource createdDomain = submitDnsDomain(dcvRequest);
        assertCreatedDomain(dcvRequest, createdDomain);

        // Create PDNS CNAME Entry for the domain with the random value
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        pdnsClient.addRandomValueToRecord(dcvRequest.domain(), randomValue, PdnsClient.PdnsRecordType.CNAME);

        // Validate the domain
        ValidateRequest validateRequest = getValidateRequest(createdDomain, DcvRequestType.DNS_CNAME);
        validateDomain(validateRequest, createdDomain.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
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

    private DomainResource submitDnsDomain(DcvRequest dcvRequest) {
        return exampleAppClient.submitDnsDomain(dcvRequest);
    }

    private void validateDomain(ValidateRequest validateRequest, long domainId) {
        exampleAppClient.validateDomain(validateRequest, domainId);
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
        assertEquals(1, createdDomain.getRandomValueDetails().size());
        DomainRandomValueDetails randomValueDetails = createdDomain.getRandomValueDetails().getFirst();
        assertNotNull(randomValueDetails.getRandomValue());
        assertNull(randomValueDetails.getEmail());
    }
}
