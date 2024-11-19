package com.digicert.validation.utils;

import java.util.Optional;

/**
 * A basic implementation of the PslOverrideSupplier interface.
 * <p>
 * This implementation of the PslOverrideSupplier interface always returns an empty Optional, indicating that no
 * overrides are available.
 */
public class NoopPslOverrideSupplier implements PslOverrideSupplier {

    /**
     * Default constructor for BasicPslOverrideSupplier.
     */
    public NoopPslOverrideSupplier() {
        // Default constructor
    }

    /**
     * Returns an empty Optional as this class does not have any overrides to supply.
     *
     * @param domain the domain for which to get the public suffix override
     * @return an empty Optional
     */
    @Override
    public Optional<String> getPublicSuffixOverride(String domain) {
        return Optional.empty();
    }
}