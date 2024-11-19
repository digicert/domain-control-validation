package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class WhoIsMethodIT {

    @Autowired
    private ExampleAppClient exampleAppClient;
    private final Long defaultAccountId = 1234L;

    @BeforeEach
    void beforeEach() throws InterruptedException {
        // This sleep is here because the Whois Server configured in ExampleDCVConfiguration is rate limited.
        // Production applications should handle this more gracefully.
        Thread.sleep(1000);
    }

    @Test
    void verifyEmailWhoIsSubmitFlow_emailsFound() {
        DcvRequest dcvRequest = new DcvRequest("markmonitor.com", defaultAccountId, DcvRequestType.EMAIL_WHOIS);

        DomainResource createdDomain = exampleAppClient.submitDnsDomain(dcvRequest);

        validateCreatedDomainData(dcvRequest, createdDomain, 1);
    }

    @Test
    void verifyEmailWhoIsSubmitFlow_noEmailsFound() {
        DcvRequest dcvRequest = new DcvRequest("digicert.com", defaultAccountId, DcvRequestType.EMAIL_WHOIS);

        assertTrue(exampleAppClient.submitDnsDomainExpectingFail(dcvRequest));
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
        });
    }
}
