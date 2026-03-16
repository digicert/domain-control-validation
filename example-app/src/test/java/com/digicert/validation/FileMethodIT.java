package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.utils.DomainUtils;
import com.digicert.validation.utils.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class FileMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    @Autowired
    private PdnsClient pdnsClient;

    @Autowired
    private DcvManager dcvManager;

    private final Long defaultAccountId = 1234L;

    @Test
    void verifyFileValidation_happyDayFlow() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_18);
        String expectedHttpUrl = "http://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        String expectedHttpsUrl = "https://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        assertTrue(lookupLocations.contains(expectedHttpUrl), "Lookup locations should include HTTP validation URL");
        assertTrue(lookupLocations.contains(expectedHttpsUrl), "Lookup locations should include HTTPS validation URL");

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeFileAuthFileWithContent("fileauth.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "fileauth.txt"), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileValidation_happyDayFlow_CustomFilename() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), "customfilename", defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_18, "customfilename");
        String expectedHttpUrl = "http://" + dcvRequest.domain() + "/.well-known/pki-validation/customfilename";
        String expectedHttpsUrl = "https://" + dcvRequest.domain() + "/.well-known/pki-validation/customfilename";
        assertTrue(lookupLocations.contains(expectedHttpUrl), "Lookup locations should include HTTP validation URL with custom filename");
        assertTrue(lookupLocations.contains(expectedHttpsUrl), "Lookup locations should include HTTPS validation URL with custom filename");
        assertEquals(2, lookupLocations.size(), "Should return exactly 2 lookup locations for file validation");

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeFileAuthFileWithContent("customfilename.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "customfilename.txt"), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileValidation_useDifferentValueAsFileName() throws IOException {
        String fileName = "some-file.txt";

        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_18);
        String expectedHttpUrl = "http://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        String expectedHttpsUrl = "https://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        assertTrue(lookupLocations.contains(expectedHttpUrl), "Lookup locations should include HTTP validation URL");
        assertTrue(lookupLocations.contains(expectedHttpsUrl), "Lookup locations should include HTTPS validation URL");
        assertEquals(2, lookupLocations.size(), "Should return exactly 2 lookup locations for file validation");

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeFileAuthFileWithContent(fileName, createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, fileName), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileValidation_useDefaultFilename() throws IOException {
        DcvRequest dcvRequest = new DcvRequest(DomainUtils.getRandomDomainName(2, "com"), defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Setup DNS record for domain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeFileAuthFileWithContent("fileauth.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, null), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileValidation_subdomainWithLookupVerification() throws IOException {
        String subdomain = "api." + DomainUtils.getRandomDomainName(2, "com");
        DcvRequest dcvRequest = new DcvRequest(subdomain, defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_18);
        String expectedHttpUrl = "http://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        String expectedHttpsUrl = "https://" + dcvRequest.domain() + "/.well-known/pki-validation/fileauth.txt";
        assertTrue(lookupLocations.contains(expectedHttpUrl), "Lookup locations should include HTTP validation URL for subdomain");
        assertTrue(lookupLocations.contains(expectedHttpsUrl), "Lookup locations should include HTTPS validation URL for subdomain");
        assertEquals(2, lookupLocations.size(), "Should return exactly 2 lookup locations for subdomain file validation");

        // Setup DNS record for subdomain
        pdnsClient.createLocalhostARecord(dcvRequest.domain());
        // Write random value to file
        FileUtils.writeFileAuthFileWithContent("fileauth.txt", createdDomain.getRandomValueDetails().getFirst().getRandomValue());

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "fileauth.txt"), createdDomain.getId());

        // Get and assert that the domain is now valid
        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    @Test
    void verifyFileValidation_lookupLocationsConsistencyTest() throws IOException {
        String testDomain = DomainUtils.getRandomDomainName(3, "org");
        DcvRequest dcvRequest = new DcvRequest(testDomain, defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        List<String> lookupLocations = dcvManager.getLookupLocations(dcvRequest.domain(), DcvMethod.BR_3_2_2_4_18);
        assertNotNull(lookupLocations, "Lookup locations should not be null");
        assertFalse(lookupLocations.isEmpty(), "Lookup locations should not be empty");
        assertEquals(2, lookupLocations.size(), "Should return exactly 2 lookup locations");

        // Verify the structure of returned URLs
        String httpUrl = lookupLocations.stream()
                .filter(url -> url.startsWith("http://"))
                .findFirst()
                .orElse(null);
        String httpsUrl = lookupLocations.stream()
                .filter(url -> url.startsWith("https://"))
                .findFirst()
                .orElse(null);

        assertNotNull(httpUrl, "Should include HTTP URL");
        assertNotNull(httpsUrl, "Should include HTTPS URL");
        assertTrue(httpUrl.contains("/.well-known/pki-validation/"), "HTTP URL should contain well-known path");
        assertTrue(httpsUrl.contains("/.well-known/pki-validation/"), "HTTPS URL should contain well-known path");
        assertTrue(httpUrl.contains(testDomain), "HTTP URL should contain the test domain");
        assertTrue(httpsUrl.contains(testDomain), "HTTPS URL should contain the test domain");

        // Additional verification: both URLs should end with the default filename
        assertTrue(httpUrl.endsWith("/fileauth.txt"), "HTTP URL should end with default filename");
        assertTrue(httpsUrl.endsWith("/fileauth.txt"), "HTTPS URL should end with default filename");
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
                .dcvRequestType(DcvRequestType.FILE_VALIDATION)
                .filename(file)
                .randomValue(createdDomain.getRandomValueDetails().getFirst().getRandomValue())
                .domain(createdDomain.getDomainName())
                .build();
    }
}
