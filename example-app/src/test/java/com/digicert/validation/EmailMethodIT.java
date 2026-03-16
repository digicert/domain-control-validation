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
import com.digicert.validation.methods.email.prepare.provider.DnsTxtEmailProvider;
import com.digicert.validation.utils.DomainUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class EmailMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    
    @Autowired
    private DcvManager dcvManager;
    
    private final PdnsClient pdnsClient = new PdnsClient();
    private final Long defaultAccountId = 1234L;

    @Test
    void verifyEmailConstructed_HappyPath() {
        // submit domain
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_CONSTRUCTED);
        DomainResource domainResource = exampleAppClient.submitDnsDomain(dcvRequest);

        // verify domain is created
        DomainResource createdDomain = exampleAppClient.getDomainResource(domainResource.getId());
        validateCreatedDomainData(dcvRequest, createdDomain, 5);

        // validate the domain
        DomainRandomValueDetails randomValue = createdDomain.getRandomValueDetails().getFirst();
        ValidateRequest validateRequest = ValidateRequest.builder()
                .dcvRequestType(dcvRequest.dcvRequestType())
                .emailAddress(randomValue.getEmail())
                .randomValue(randomValue.getRandomValue())
                .domain(dcvRequest.domain())
                .build();

        exampleAppClient.validateDomain(validateRequest, domainResource.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(domainResource.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
        
        // Verify DcvManager.getLookupLocations() for Email Constructed method
        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_4);
        assertNotNull(lookupLocations, "Email Constructed lookup locations should not be null");
        assertFalse(lookupLocations.isEmpty(), "Email Constructed lookup locations should not be empty");
        assertTrue(lookupLocations.stream().anyMatch(email -> email.contains(dcvRequest.domain())), 
                   "Lookup locations should contain domain: " + dcvRequest.domain());
    }

    @Test
    void verifyEmailDnsTxtSubmitFlow_HappyPath() {
        // create domain request with email dns txt
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_TXT);

        // add email as a dns txt record
        String prefixedDomainName = String.format("%s.%s", DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX,
                dcvRequest.domain());
        pdnsClient.addRandomValueToRecord(prefixedDomainName, List.of("admin@"+dcvRequest.domain()), PdnsClient.PdnsRecordType.TXT, "");

        // submit domain
        DomainResource domainResource = exampleAppClient.submitDnsDomain(dcvRequest);

        // verify domain is created
        DomainResource createdDomain = exampleAppClient.getDomainResource(domainResource.getId());
        validateCreatedDomainData(dcvRequest, createdDomain, 1);

        // build the validation request
        DomainRandomValueDetails randomValue = createdDomain.getRandomValueDetails().getFirst();
        ValidateRequest validateRequest = ValidateRequest.builder()
                .dcvRequestType(dcvRequest.dcvRequestType())
                .emailAddress(randomValue.getEmail())
                .randomValue(randomValue.getRandomValue())
                .domain(dcvRequest.domain())
                .build();

        // validate the domain
        exampleAppClient.validateDomain(validateRequest, domainResource.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(domainResource.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }


    @Test
    void verifyEmailDnsCaaSubmitFlow_HappyPath() {
        // create domain request with email dns caa
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_CAA);
        String caaEmail = "caaemail@domain.com";

        // add email as a dns caa record
        pdnsClient.addCaaRecord(dcvRequest.domain(), List.of(caaEmail, "invalid-email"));

        // submit domain
        DomainResource domainResource = exampleAppClient.submitDnsDomain(dcvRequest);
        assertEquals(domainResource.getRandomValueDetails().size(), 1);

        // verify domain is created
        DomainResource createdDomain = exampleAppClient.getDomainResource(domainResource.getId());
        validateCreatedDomainData(dcvRequest, createdDomain, 1);

        // build the validation request
        DomainRandomValueDetails randomValue = createdDomain.getRandomValueDetails().getFirst();
        ValidateRequest validateRequest = ValidateRequest.builder()
                .dcvRequestType(dcvRequest.dcvRequestType())
                .emailAddress(randomValue.getEmail())
                .randomValue(randomValue.getRandomValue())
                .domain(dcvRequest.domain())
                .build();

        // validate the domain
        exampleAppClient.validateDomain(validateRequest, domainResource.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(domainResource.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyEmailDnsCaaSubmitFlow_badRequest_noCaaEmails() {
        // create domain request with email dns txt
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_CAA);

        // verify bad request when no caa email is present
        assertTrue(exampleAppClient.submitDnsDomainExpectingFail(dcvRequest));
    }

    @Test
    void verifyEmailDnsTxtSubmitFlow_EmailDoesNotMatchDomain() {
        // create domain request with email dns txt
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_TXT);

        // add email as a dns txt record that does not match the domain
        pdnsClient.addRandomValueToRecord(DomainUtils.getRandomDomainName(2, "com"), List.of("admin@"+dcvRequest.domain()), PdnsClient.PdnsRecordType.TXT, "");

        // submit domain
        assertTrue(exampleAppClient.submitDnsDomainExpectingFail(dcvRequest));
    }

    @Test
    void verifyEmailDnsTxtSubmitFlow_multi_HappyPath() {
        // create domain request with email dns txt
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_TXT);

        List<String> emails = List.of("admin@"+dcvRequest.domain(),
                "administrator@"+dcvRequest.domain(),
                "webmaster@"+dcvRequest.domain(),
                "hostmaster@"+dcvRequest.domain(),
                "postmaster@"+dcvRequest.domain());

        // add email as a dns txt record
        String prefixedDomainName = String.format("%s.%s", DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX,
                dcvRequest.domain());
        pdnsClient.addRandomValueToRecord(prefixedDomainName, emails, PdnsClient.PdnsRecordType.TXT, "");

        // submit domain
        DomainResource domainResource = exampleAppClient.submitDnsDomain(dcvRequest);

        // verify domain is created
        DomainResource createdDomain = exampleAppClient.getDomainResource(domainResource.getId());
        validateCreatedDomainData(dcvRequest, createdDomain, 5);

        // build the validation request
        DomainRandomValueDetails randomValue = createdDomain.getRandomValueDetails().getFirst();
        ValidateRequest validateRequest = ValidateRequest.builder()
                .dcvRequestType(dcvRequest.dcvRequestType())
                .emailAddress(randomValue.getEmail())
                .randomValue(randomValue.getRandomValue())
                .domain(dcvRequest.domain())
                .build();

        // validate the domain
        exampleAppClient.validateDomain(validateRequest, domainResource.getId());

        // verify domain is showing as valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(domainResource.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyEmailDnsTxtSubmitFlow_NoEmailFound() {
        // create domain request with email dns txt but do not create dns txt record with email
        DcvRequest dcvRequest = createDcvRequest(DomainUtils.getRandomDomainName(2, "com"), DcvRequestType.EMAIL_DNS_TXT);

        assertTrue(exampleAppClient.submitDnsDomainExpectingFail(dcvRequest));
    }

    private DcvRequest createDcvRequest(String domainName, DcvRequestType dcvRequestType) {
        return new DcvRequest(domainName, defaultAccountId, dcvRequestType);
    }

    private void validateCreatedDomainData(DcvRequest dcvRequest, DomainResource createdDomain, int expectedRandomValues) {
        assertNotNull(createdDomain);
        assertNotEquals(0, createdDomain.getId());
        assertEquals(dcvRequest.domain(), createdDomain.getDomainName());
        assertEquals(dcvRequest.accountId(), createdDomain.getAccountId());
        assertEquals(dcvRequest.dcvRequestType(), createdDomain.getDcvType());
        assertEquals(DcvRequestStatus.PENDING, createdDomain.getStatus());
        assertEquals(expectedRandomValues, createdDomain.getRandomValueDetails().size());
        createdDomain.getRandomValueDetails().forEach(domainRandomValueResource -> {
            assertNotNull(domainRandomValueResource.getRandomValue());
            assertNotNull(domainRandomValueResource.getEmail());
            assertNotNull(domainRandomValueResource.getDnsRecordName());
        });
    }
}
