package com.digicert.validation.client;

import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import static org.junit.jupiter.api.Assertions.*;

@Service
public class ExampleAppClient {

    @Autowired
    private TestRestTemplate testRestTemplate;

    public DomainResource submitDnsDomain(DcvRequest dcvRequest) {
        ResponseEntity<DomainResource> createResponse = testRestTemplate.exchange("/domains", HttpMethod.POST, new HttpEntity<>(dcvRequest), DomainResource.class);

        assertTrue(createResponse.getStatusCode().is2xxSuccessful());
        DomainResource domainResource = createResponse.getBody();

        assertNotNull(domainResource);
        assertNotEquals(0, domainResource.getId());
        return domainResource;
    }

    public boolean submitDnsDomainExpectingFail(DcvRequest dcvRequest) {
        ResponseEntity<DomainResource> createResponse = testRestTemplate.exchange("/domains", HttpMethod.POST, new HttpEntity<>(dcvRequest), DomainResource.class);

        assertFalse(createResponse.getStatusCode().is2xxSuccessful());
        return true;
    }

    public void validateDomain(ValidateRequest validateRequest, long domainId) {
        testRestTemplate.put("/domains/{domainId}", validateRequest, domainId);

        // Verify that the domain is showing as valid
        DomainResource domainResource = getDomainResource(domainId);
        assertEquals(DcvRequestStatus.VALID, domainResource.getStatus());
    }

    public DomainResource getDomainResource(long domainId) {
        ResponseEntity<DomainResource> getResponse = testRestTemplate.getForEntity("/domains/" + domainId, DomainResource.class);

        assertTrue(getResponse.getStatusCode().is2xxSuccessful());
        return getResponse.getBody();
    }

    public void submitAccountTokenKey(long accountId, String tokenKey) {
        testRestTemplate.postForEntity("/accounts/{accountId}/tokens?tokenKey={tokenKey}", null, Void.class, accountId, tokenKey);
    }
}
