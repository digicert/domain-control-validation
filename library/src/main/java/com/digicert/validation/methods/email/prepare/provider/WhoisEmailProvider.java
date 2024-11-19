package com.digicert.validation.methods.email.prepare.provider;

/**
 * WhoisEmailProvider is an interface that extends EmailProvider to provide email contacts for a domain
 * using WHOIS data.
 * <p>
 * The WhoisEmailProvider interface is designed to facilitate the retrieval of email contacts from WHOIS records.
 * Implementations of this interface are expected to query WHOIS databases and extract relevant
 * email addresses for domain validation purposes.
 */
public interface WhoisEmailProvider extends EmailProvider {
}