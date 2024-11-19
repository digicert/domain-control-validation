package com.digicert.validation.utils;

import com.digicert.validation.exceptions.InputException;

import java.util.Optional;

/**
 * Interface for providing overrides for the public suffix of a domain.
 * <p>
 * Overrides are considered when determining the base domain of a given domain. Overrides can be used in special cases
 * to change which part of a domain should be considered its TLD. For example, blogspot.com is an addressable domain
 * even though it is normally treated like a TLD. As such, "example.blogspot.com" would be treated as a base domain,
 * and "blogspot.com" would be considered invalid. An override could be set up to consider "blogspot.com" as a base
 * domain while still treating "example.blogspot.com" as a base domain as well.
 */
public interface PslOverrideSupplier {

    /**
     * Returns an override for the public suffix of a domain.
     * <p>
     * This method is called when determining the base domain of an FQDN, and checks if there is an override for
     * the public suffix of the FQDN. If there is an override present, it returns an Optional containing the
     * portion of the FQDN to treat as a TLD. If no override is needed, it returns an empty Optional.
     * <p>
     * For example, blogspot.com is normally treated as a TLD. If this method were to return an optional containing
     * "com", the library would report that "blogspot.com" is its own base domain. Lacking such an override, the library
     * will throw an exception instead.
     * <p>
     * Overrides do not have to be the same for a domain and its subdomains. Following the above example, when this
     * method is given "example.blogspot.com" it could return an empty optional, allowing for "example.blogspot.com"
     * to still be considered its own base domain.
     * <p>
     * To have a domain be considered invalid, simply throw an InputException.
     *
     * @param domain the domain to check for an override
     * @return an Optional containing the portion of the domain to treat as a TLD, or an empty Optional if no override is present
     * @throws InputException if the TLD should be invalid
     */
    Optional<String> getPublicSuffixOverride(String domain) throws InputException;
}