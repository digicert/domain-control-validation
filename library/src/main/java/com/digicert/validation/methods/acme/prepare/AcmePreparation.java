package com.digicert.validation.methods.acme.prepare;

/**
 * Represents the preparation details required for ACME validation.
 * This record holds the domain that needs to be validated
 *
 * @param domain the domain to be validated
 */
public record AcmePreparation(String domain) {
}