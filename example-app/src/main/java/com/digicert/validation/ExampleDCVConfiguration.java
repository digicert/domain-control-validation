package com.digicert.validation;

import com.digicert.validation.psl.CustomPslOverrideSupplier;
import com.digicert.validation.service.whois.BasicWhoIsEmailProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class ExampleDCVConfiguration {

    @Bean
    DcvManager dcvManager(CustomPslOverrideSupplier customPslOverrideSupplier,
                          BasicWhoIsEmailProvider whoisEmailProvider) {
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                // set the DNS servers to use for DNS lookups
                .dnsServers(List.of("localhost:10000"))
                // Configured to match the value configured in powerdns docker container
                .pslOverrideSupplier(customPslOverrideSupplier)
                .whoisEmailProvider(whoisEmailProvider)
                .build();

        return new DcvManager.Builder()
                .withDcvConfiguration(dcvConfiguration)
                .build();
    }
}
