package com.digicert.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DcvManagerTest {

    private DcvConfiguration dcvConfiguration;

    @BeforeEach
    void setUp() {
        dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("8.8.8.8"))
                .build();
    }

    @Test
    void testBuilderWithValidDcvConfiguration() {
        dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("8.8.8.8"))
                .build();

        DcvManager dcvManager = new DcvManager.Builder()
                .withDcvConfiguration(dcvConfiguration)
                .build();

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
}