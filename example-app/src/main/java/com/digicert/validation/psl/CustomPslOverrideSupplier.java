package com.digicert.validation.psl;

import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.digicert.validation.utils.PslOverrideSupplier;

@Service
public class CustomPslOverrideSupplier implements PslOverrideSupplier {

    // Map of domain suffixes to override
    private final Map<String, String> overridePublicSuffixes = Map.of("ac.gov.br","gov.br");

    @Override
    public Optional<String> getPublicSuffixOverride(String domain) {


        // first check if the domain is in the override list
        return overridePublicSuffixes.entrySet().stream()
                .filter(entry -> domain.endsWith(entry.getKey()))
                .filter(entry -> domain.equals(entry.getKey()) ||
                        domain.endsWith("." + entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst();
    }
}