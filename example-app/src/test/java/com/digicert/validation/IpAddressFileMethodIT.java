package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.config.AllowReservedIpDcvConfiguration;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.utils.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for IP address file validation (BR 3.2.2.5.1) via the DCV library.
 * <p>
 * These tests verify that the file validation method works correctly when the subject is an
 * IP address rather than a domain name. All tests use {@link AllowReservedIpDcvConfiguration}
 * so that the local Docker nginx ({@code 127.0.0.1}) can serve the validation file.
 * <p>
 * Rejection tests for reserved/private IP addresses (when {@code allowReservedIpAddresses=false})
 * are in {@link IpAddressFileRejectionIT}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Import(AllowReservedIpDcvConfiguration.class)
class IpAddressFileMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    private final Long defaultAccountId = 1234L;

    // -----------------------------------------------------------------------
    // Happy-path tests — allowReservedIpAddresses=true via @Import
    // -----------------------------------------------------------------------

    /**
     * Verifies that file validation succeeds when the subject is a loopback IPv4 address
     * ({@code 127.0.0.1}) and the library is configured to allow reserved IP addresses.
     * <p>
     * The nginx Docker container serves files at {@code 127.0.0.1}, so this test validates
     * the full end-to-end flow for IP address subjects using the default filename.
     */
    @Test
    void verifyFileValidation_ipv4Address_happyDayFlow() throws IOException {
        String ipAddress = "127.0.0.1";
        DcvRequest dcvRequest = new DcvRequest(ipAddress, defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        // Write the random value to the default file path served by nginx
        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        FileUtils.writeFileAuthFileWithContent("fileauth.txt", randomValue);

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "fileauth.txt"), createdDomain.getId());

        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    /**
     * Verifies that file validation succeeds for an IPv4 address subject when a custom
     * filename is specified in the prepare request.
     */
    @Test
    void verifyFileValidation_ipv4Address_customFilename() throws IOException {
        String ipAddress = "127.0.0.1";
        DcvRequest dcvRequest = new DcvRequest(ipAddress, "ip-custom-file", defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        FileUtils.writeFileAuthFileWithContent("ip-custom-file.txt", randomValue);

        exampleAppClient.validateDomain(createValidateRequest(createdDomain, "ip-custom-file.txt"), createdDomain.getId());

        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    /**
     * Verifies that file validation succeeds when the subject is a loopback IPv4 address
     * and the validate request passes a custom filename that differs from the default.
     */
    @Test
    void verifyFileValidation_ipv4Address_useDefaultFilename() throws IOException {
        String ipAddress = "127.0.0.1";
        DcvRequest dcvRequest = new DcvRequest(ipAddress, defaultAccountId, DcvRequestType.FILE_VALIDATION);
        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        assertCreatedDomain(createdDomain, dcvRequest);

        String randomValue = createdDomain.getRandomValueDetails().getFirst().getRandomValue();
        FileUtils.writeFileAuthFileWithContent("fileauth.txt", randomValue);

        // Pass null filename — should fall back to the library's default ("fileauth.txt")
        exampleAppClient.validateDomain(createValidateRequest(createdDomain, null), createdDomain.getId());

        DomainResource verifiedDomain = exampleAppClient.getDomainResource(createdDomain.getId());
        assertEquals(DcvRequestStatus.VALID, verifiedDomain.getStatus());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void assertCreatedDomain(DomainResource createdDomain, DcvRequest dcvRequest) {
        assertNotNull(createdDomain);
        assertNotEquals(0, createdDomain.getId());
        assertEquals(dcvRequest.domain(), createdDomain.getDomainName());
        assertEquals(dcvRequest.accountId(), createdDomain.getAccountId());
        assertEquals(dcvRequest.dcvRequestType(), createdDomain.getDcvType());
        assertEquals(DcvRequestStatus.PENDING, createdDomain.getStatus());
        assertEquals(1, createdDomain.getRandomValueDetails().size());
        createdDomain.getRandomValueDetails().forEach(detail -> {
            assertNotNull(detail.getRandomValue());
            assertNull(detail.getEmail());
        });
    }

    private static ValidateRequest createValidateRequest(DomainResource createdDomain, String filename) {
        return ValidateRequest.builder()
                .dcvRequestType(DcvRequestType.FILE_VALIDATION)
                .filename(filename)
                .randomValue(createdDomain.getRandomValueDetails().getFirst().getRandomValue())
                .domain(createdDomain.getDomainName())
                .build();
    }
}
