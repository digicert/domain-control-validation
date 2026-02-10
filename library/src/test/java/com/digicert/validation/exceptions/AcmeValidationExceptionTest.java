package com.digicert.validation.exceptions;

import com.digicert.validation.enums.AcmeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import com.digicert.validation.mpic.api.dns.DnssecError;
import com.digicert.validation.mpic.api.dns.DnssecStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AcmeValidationExceptionTest {

    @Test
    void testAcmeDnsValidationException_with_dcvErrorAndRequest() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.RANDOM_VALUE_NOT_FOUND;

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request);

        // Then
        assertNotNull(exception);
        assertEquals(request, exception.getAcmeValidationRequest());
        assertTrue(exception.getErrors().contains(dcvError));
        assertNull(exception.getDnssecDetails());
    }

    @Test
    void testAcmeDnsValidationException_with_dcvErrorRequestAndDnssecDetails() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        DnssecDetails dnssecDetails = new DnssecDetails(
            DnssecStatus.BOGUS,
            DnssecError.DNSSEC_BOGUS,
            "example.com",
            "Signature verification failed"
        );

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        // Then
        assertNotNull(exception);
        assertEquals(request, exception.getAcmeValidationRequest());
        assertTrue(exception.getErrors().contains(dcvError));
        assertNotNull(exception.getDnssecDetails());
        assertEquals(dnssecDetails, exception.getDnssecDetails());
        assertEquals(DnssecStatus.BOGUS, exception.getDnssecDetails().dnssecStatus());
        assertEquals(DnssecError.DNSSEC_BOGUS, exception.getDnssecDetails().dnssecError());
        assertEquals("example.com", exception.getDnssecDetails().errorLocation());
        assertEquals("Signature verification failed", exception.getDnssecDetails().errorDetails());
    }

    @Test
    void testAcmeDnsValidationException_with_dnssecDetailsPreservesDnssecInfo() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        DnssecDetails dnssecDetails = new DnssecDetails(
            DnssecStatus.INDETERMINATE,
            DnssecError.DNSKEY_MISSING,
            "_acme-challenge.example.com",
            "DNSKEY not found at zone apex"
        );

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        // Then
        assertNotNull(exception.getDnssecDetails());
        assertEquals(DnssecStatus.INDETERMINATE, exception.getDnssecDetails().dnssecStatus());
        assertEquals(DnssecError.DNSKEY_MISSING, exception.getDnssecDetails().dnssecError());
        assertEquals("_acme-challenge.example.com", exception.getDnssecDetails().errorLocation());
        assertEquals("DNSKEY not found at zone apex", exception.getDnssecDetails().errorDetails());
    }

    @Test
    void testAcmeDnsValidationException_with_dnssecDetails() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, null);

        // Then
        assertNotNull(exception);
        assertEquals(request, exception.getAcmeValidationRequest());
        assertTrue(exception.getErrors().contains(dcvError));
        assertNull(exception.getDnssecDetails());
    }

    @Test
    void testAcmeDnsValidationException_with_differentDnssecStatuses() {
        // Test with SECURE status
        testWithDnssecStatus(DnssecStatus.SECURE, null);

        // Test with INSECURE status
        testWithDnssecStatus(DnssecStatus.INSECURE, null);

        // Test with BOGUS status
        testWithDnssecStatus(DnssecStatus.BOGUS, DnssecError.DNSSEC_BOGUS);

        // Test with INDETERMINATE status
        testWithDnssecStatus(DnssecStatus.INDETERMINATE, DnssecError.OTHER);

        // Test with NOT_CHECKED status
        testWithDnssecStatus(DnssecStatus.NOT_CHECKED, null);
    }

    @Test
    void testAcmeDnsValidationException_with_differentDnssecErrors() {
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;

        // Test each DNSSEC error type
        for (DnssecError dnssecError : DnssecError.values()) {
            DnssecDetails dnssecDetails = new DnssecDetails(
                DnssecStatus.BOGUS,
                dnssecError,
                "example.com",
                "Error: " + dnssecError.name()
            );

            AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

            assertNotNull(exception.getDnssecDetails());
            assertEquals(dnssecError, exception.getDnssecDetails().dnssecError());
        }
    }

    @Test
    void testAcmeDnsValidationException_with_messageContainsDcvError() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        DnssecDetails dnssecDetails = new DnssecDetails(
            DnssecStatus.BOGUS,
            DnssecError.DNSSEC_BOGUS,
            "example.com",
            "Signature verification failed"
        );

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        // Then
        assertNotNull(exception.getMessage());
        assertTrue(exception.getErrors().contains(dcvError));
    }

    @Test
    void testAcmeValidationRequestPreservedAcrossBothConstructors() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.RANDOM_VALUE_NOT_FOUND;

        // When
        AcmeValidationException exception1 = new AcmeValidationException(dcvError, request);
        AcmeValidationException exception2 = new AcmeValidationException(
            DcvError.DNS_LOOKUP_DNSSEC_FAILURE,
            request,
            new DnssecDetails(DnssecStatus.BOGUS, DnssecError.DNSSEC_BOGUS, "example.com", "error")
        );

        // Then
        assertEquals(request, exception1.getAcmeValidationRequest());
        assertEquals(request, exception2.getAcmeValidationRequest());
        assertEquals(exception1.getAcmeValidationRequest().getDomain(),
                     exception2.getAcmeValidationRequest().getDomain());
    }

    @Test
    void testDnssecDetailsWithCompleteInformation() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        String errorLocation = "_acme-challenge.test.example.com";
        String errorDetails = "RRSIG signature verification failed: signature expired";
        DnssecDetails dnssecDetails = new DnssecDetails(
            DnssecStatus.BOGUS,
            DnssecError.RRSIGS_MISSING,
            errorLocation,
            errorDetails
        );

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        // Then
        assertNotNull(exception.getDnssecDetails());
        assertEquals(DnssecStatus.BOGUS, exception.getDnssecDetails().dnssecStatus());
        assertEquals(DnssecError.RRSIGS_MISSING, exception.getDnssecDetails().dnssecError());
        assertEquals(errorLocation, exception.getDnssecDetails().errorLocation());
        assertEquals(errorDetails, exception.getDnssecDetails().errorDetails());
    }

    @Test
    void testDnssecDetailsNotChecked() {
        // Given
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        DnssecDetails dnssecDetails = DnssecDetails.notChecked();

        // When
        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        // Then
        assertNotNull(exception.getDnssecDetails());
        assertEquals(DnssecStatus.NOT_CHECKED, exception.getDnssecDetails().dnssecStatus());
        assertNull(exception.getDnssecDetails().dnssecError());
        assertNull(exception.getDnssecDetails().errorLocation());
        assertNull(exception.getDnssecDetails().errorDetails());
    }

    private void testWithDnssecStatus(DnssecStatus status, DnssecError error) {
        AcmeValidationRequest request = createSampleRequest();
        DcvError dcvError = DcvError.DNS_LOOKUP_DNSSEC_FAILURE;
        DnssecDetails dnssecDetails = new DnssecDetails(status, error, "example.com", "test error");

        AcmeValidationException exception = new AcmeValidationException(dcvError, request, dnssecDetails);

        assertNotNull(exception.getDnssecDetails());
        assertEquals(status, exception.getDnssecDetails().dnssecStatus());
        assertEquals(error, exception.getDnssecDetails().dnssecError());
    }

    private AcmeValidationRequest createSampleRequest() {
        return AcmeValidationRequest.builder()
            .domain("example.com")
            .acmeType(AcmeType.ACME_DNS_01)
            .acmeThumbprint("test-thumbprint")
            .randomValue("random-value-123")
            .build();
    }
}
