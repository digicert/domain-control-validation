package com.digicert.validation.methods.email.prepare.provider;

import java.util.Set;

/**
 * A Noop provider that returns an empty set of emails. For the purpose of resolving unused dependencies.
 * Consumers should provide an WhoisEmailProvider implementation.
 * BasicWhoIsEmailProvider in the example-app for an example implementation.
 */
public class NoopWhoisEmailProvider implements WhoisEmailProvider{
    /**
     * Default noop constructor.
     */
    public NoopWhoisEmailProvider() {
        // Default constructor
    }
    @Override
    public Set<String> findEmailsForDomain(String domain) {
        return Set.of();
    }
}
