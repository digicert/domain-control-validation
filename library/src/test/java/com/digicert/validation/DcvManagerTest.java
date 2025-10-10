package com.digicert.validation;

import com.digicert.validation.enums.DcvMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DcvManagerTest {

    private DcvConfiguration dcvConfiguration;
    private DcvManager dcvManager;

    @BeforeEach
    void setUp() {
        dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("8.8.8.8"))
                .build();
        
        dcvManager = new DcvManager.Builder()
                .withDcvConfiguration(dcvConfiguration)
                .build();
    }

    @Test
    void testBuilderWithValidDcvConfiguration() {
        // Use the dcvManager created in setUp() to verify it was built correctly
        assertNotNull(dcvManager);
        assertNotNull(dcvManager.getDnsValidator());
        assertNotNull(dcvManager.getEmailValidator());
        assertNotNull(dcvManager.getFileValidator());
    }

    @Test
    void testBuilderWithNullDcvConfiguration() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvManager.Builder().withDcvConfiguration(null));
        assertEquals("DcvConfiguration cannot be null", exception.getMessage());
    }

    @Test
    void testGetLookupLocations_DnsChange() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_7);
        
        assertNotNull(locations);
        assertFalse(locations.isEmpty());
        
        // Should contain _dnsauth prefixed domains and direct domains
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("_dnsauth.")));
        assertTrue(locations.contains(domain));
    }

    @Test
    void testGetLookupLocations_FileValidation() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_18);
        
        assertNotNull(locations);
        assertEquals(2, locations.size());
        
        // Should contain both HTTP and HTTPS URLs
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("http://")));
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("https://")));
        assertTrue(locations.stream().allMatch(loc -> loc.contains("/.well-known/pki-validation/")));
    }

    @Test
    void testGetLookupLocations_AcmeHttpValidation() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_19);
        
        assertNotNull(locations);
        assertEquals(2, locations.size());
        
        // Should contain both HTTP and HTTPS URLs with ACME challenge path
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("http://")));
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("https://")));
        assertTrue(locations.stream().allMatch(loc -> loc.contains("/.well-known/acme-challenge/")));
    }

    @Test
    void testGetLookupLocations_ConstructedEmail() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_4);
        
        assertNotNull(locations);
        assertFalse(locations.isEmpty());
        
        // Should contain constructed email addresses
        assertTrue(locations.contains("admin@" + domain));
        assertTrue(locations.contains("administrator@" + domain));
        assertTrue(locations.contains("webmaster@" + domain));
        assertTrue(locations.contains("hostmaster@" + domain));
        assertTrue(locations.contains("postmaster@" + domain));
    }

    @Test
    void testGetLookupLocations_EmailDnsTxtContact() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_14);
        
        assertNotNull(locations);
        assertFalse(locations.isEmpty());
        
        // Should contain DNS TXT contact lookup location
        assertTrue(locations.contains("_validation-contactemail." + domain));
    }

    @Test
    void testGetLookupLocations_EmailDnsCaaContact() {
        String domain = "test.example.com";
        List<String> locations = dcvManager.getLookupLocations(domain, DcvMethod.BR_3_2_2_4_13);
        
        assertNotNull(locations);
        assertFalse(locations.isEmpty());
        
        // Should contain the domain itself for CAA record lookup
        assertTrue(locations.contains(domain));
    }

    @Test
    void testGetLookupLocations_UnsupportedMethod() {
        String domain = "test.example.com";
        
        UnsupportedOperationException exception = assertThrows(
            UnsupportedOperationException.class, 
            () -> dcvManager.getLookupLocations(domain, DcvMethod.UNKNOWN)
        );
        
        assertTrue(exception.getMessage().contains("Lookup locations not supported for method"));
    }

    @Test
    void testGetLookupLocations_EmptyDomain() {
        // Test with empty domain - should not throw exception but may return empty or basic results
        assertDoesNotThrow(() -> {
            List<String> locations = dcvManager.getLookupLocations("", DcvMethod.BR_3_2_2_4_7);
            assertNotNull(locations);
        });
    }

    @Test
    void testGetLookupLocations_SubdomainHandling() {
        String subdomain = "api.app.example.com";
        List<String> locations = dcvManager.getLookupLocations(subdomain, DcvMethod.BR_3_2_2_4_7);
        
        assertNotNull(locations);
        assertFalse(locations.isEmpty());
        
        // Should contain both prefixed and direct domains, including parent domains
        assertTrue(locations.stream().anyMatch(loc -> loc.startsWith("_dnsauth.")));
        assertTrue(locations.contains(subdomain));
        
        // Should handle domain hierarchy (getDomainAndParents functionality)
        assertTrue(locations.size() > 2); // Should have multiple entries for domain hierarchy
    }
}