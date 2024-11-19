package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.exceptions.PreparationException;

import java.util.Set;

/**
 * EmailProvider is an interface for classes that provide email contacts for domain validation.
 * <p>
 * This interface defines the contract for any class that aims to retrieve email contacts associated with a specific domain.
 * Implementations of this interface are expected to provide the logic for querying and extracting email addresses from various
 * sources, such as DNS TXT records, databases, or other external services.
 */
public interface EmailProvider {

    /**
     * Retrieves email contacts for the given domain.
     * <p>
     * This method is responsible for obtaining a set of email addresses associated with the specified domain. The implementation
     * should ensure that the email addresses returned are valid and relevant for the domain validation process.
     *
     * @param domain the domain to retrieve email contacts for
     * @return a set of email contacts for the domain
     * @throws PreparationException if an error occurs while retrieving email contacts for the domain
     */
    Set<String> findEmailsForDomain(String domain) throws PreparationException;
}