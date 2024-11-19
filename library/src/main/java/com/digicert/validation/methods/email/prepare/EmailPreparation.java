package com.digicert.validation.methods.email.prepare;

/**
 * Represents the preparation details for email validation.
 * <p>
 * This record encapsulates the necessary details required for preparing an email validation process.
 * The domain field represents the domain name that needs to be validated, ensuring that the email
 * originates from a legitimate source. The emailSource field indicates the source of the email,
 * which could be used to determine the authenticity and origin of the email for validation purposes.
 *
 * @param domain      The domain to be validated.
 * @param emailSource The source of the email for validation.
 */
public record EmailPreparation(String domain, EmailSource emailSource) {
}