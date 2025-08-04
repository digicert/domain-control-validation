package com.digicert.validation.methods.email.prepare;

/**
 * This class is used to store the email address and the random value that was sent to the email address.
 * <p>
 * The `EmailWithRandomValue` class is a record that encapsulates an email address, a corresponding random value and a
 * DSN record name when applicable. The DNS record name is associated with emails discovered via DNS TXT and CAA lookups.
 * The random value is used in the email validation process in order verify the ownership
 * of an email address.
 *
 * @param email The email address.
 *              <p>
 *              The `email` parameter represents the email address that is being validated. It is a string that should conform to standard
 *              email format rules.
 *
 * @param randomValue   The random value that was sent to the email address.
 *                      <p>
 *                      The `randomValue` parameter is a string that contains a randomly generated value sent to the email address. This value is
 *                      used as a verification code to confirm that the email address is valid and accessible by the intended recipient.
 *
 * @param dnsRecordName The DNS record name that was used to retrieve the email address.
 */
public record EmailWithRandomValue(String email, String randomValue, String dnsRecordName) { }