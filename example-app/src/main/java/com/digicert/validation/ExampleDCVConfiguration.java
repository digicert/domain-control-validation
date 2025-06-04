package com.digicert.validation;

import com.digicert.validation.psl.CustomPslOverrideSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class ExampleDCVConfiguration {

    @Bean
    DcvManager dcvManager(CustomPslOverrideSupplier customPslOverrideSupplier) {
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                // set the DNS servers to use for DNS lookups
                .dnsServers(List.of("localhost:10000"))
                // Configured to match the value configured in powerdns docker container
                .pslOverrideSupplier(customPslOverrideSupplier)
                .build();

        return new DcvManager.Builder()
                .withDcvConfiguration(dcvConfiguration)
                .build();
    }
}
