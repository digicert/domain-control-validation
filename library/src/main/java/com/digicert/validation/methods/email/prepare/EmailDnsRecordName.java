package com.digicert.validation.methods.email.prepare;

/**
 * Represents an email address and its associated DNS record name if applicable.
 * @param email An email address used in validation.
 * @param dnsRecordName When present this is the DNS record name that was used to retrieve the email address.
 *                      Applicable when using DNS TXT or DNS CAA based emails.
 */
public record EmailDnsRecordName (String email, String dnsRecordName){
}
