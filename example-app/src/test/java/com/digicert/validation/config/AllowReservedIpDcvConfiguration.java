package com.digicert.validation.config;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvManager;
import com.digicert.validation.mpic.MpicClientImpl;
import com.digicert.validation.psl.CustomPslOverrideSupplier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;

/**
 * Test-only Spring configuration that overrides the production {@link com.digicert.validation.ExampleDCVConfiguration}
 * DcvManager bean with one that has {@code allowReservedIpAddresses=true}.
 * <p>
 * This is required for integration tests that exercise IP address validation against the local Docker
 * infrastructure (nginx serving files at {@code 127.0.0.1}), where the validation target necessarily
 * uses private/loopback IP space.
 * <p>
 * <strong>WARNING: This configuration must never be used in production.</strong>
 */
@TestConfiguration
public class AllowReservedIpDcvConfiguration {

    @Bean
    @Primary
    DcvManager allowReservedIpDcvManager(CustomPslOverrideSupplier customPslOverrideSupplier,
                                         MpicClientImpl mpicClientImpl) {
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("localhost:10000"))
                .pslOverrideSupplier(customPslOverrideSupplier)
                .mpicClientInterface(mpicClientImpl)
                // Allow reserved IPs so that the local Docker nginx (127.0.0.1) can be used as a
                // validation target in integration tests. Must never be set true in production.
                .allowReservedIpAddresses(true)
                .build();

        return new DcvManager.Builder()
                .withDcvConfiguration(dcvConfiguration)
                .build();
    }
}
