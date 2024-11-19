package com.digicert.validation.enums;

import lombok.Getter;

/**
 * Enum representing the possible domain validation methods.
 * <p>
 * Brief Description of the DCV Methods:
 * <ul>
 *     <li>3.2.2.4.1 -> NOT Allowed</li>
 *     <li><b>3.2.2.4.2 -> Email (whois)</b></li>
 *     <li>3.2.2.4.3 -> Phone - NOT Allowed</li>
 *     <li><b>3.2.2.4.4 -> Email to constructed email address</b></li>
 *     <li>3.2.2.4.5 -> NOT Allowed</li>
 *     <li>3.2.2.4.6 -> NOT Allowed</li>
 *     <li><b>3.2.2.4.7 - DNS Change</b></li>
 *     <li>3.2.2.4.8 -> IP Address - Not Supported</li>
 *     <li>3.2.2.4.9 -> NOT Allowed</li>
 *     <li>3.2.2.4.10 -> NOT Allowed</li>
 *     <li>3.2.2.4.11 -> NOT Allowed</li>
 *     <li>3.2.2.4.12 -> Validating applicant as a Domain Contact - Not Supported</li>
 *     <li>3.2.2.4.13 -> Email to DNS CAA Contact - Not Supported</li>
 *     <li><b>3.2.2.4.14 -> Email to DNS TXT Contact</b></li>
 *     <li>3.2.2.4.15 / 16 / 17 -> Phone Contact - Not Supported</li>
 *     <li><b>3.2.2.4.18 -> File Auth</b></li>
 *     <li>3.2.2.4.19 -> ACME details - Not Supported</li>
 *     <li>3.2.2.4.20 -> TLS</li>
 *   </ul>
 *
 * @see com.digicert.validation.methods.dns.DnsValidator
 * @see com.digicert.validation.methods.email.EmailValidator
 * @see com.digicert.validation.methods.fileauth.FileAuthValidator
 */
@Getter
public enum DcvMethod {
    /**
     * Email to Domain Contact.
     * <br>
     * This method involves sending an email to a domain contact, as listed in the WHOIS database for the domain.
     * The email will contain a random value that the recipient can use to confirm control over the domain.
     */
    BR_3_2_2_4_2("3.2.2.4.2"),

    /**
     * Constructed Email to Domain Contact.
     * <p>
     * This method involves sending an email to a constructed address based on the domain, such as admin@domain.com.
     * The email will contain a random value that the recipient can use to confirm control over the domain.
     * <p>
     * The constructed emails are:
     * <ul>
     * <li>admin@</li>
     * <li>administrator@</li>
     * <li>webmaster@</li>
     * <li>hostmaster@</li>
     * <li>postmaster@</li>
     * </ul>
     */
    BR_3_2_2_4_4("3.2.2.4.4"),

    /**
     * DNS Change.
     * <p>
     * This method requires the domain owner to create a specific DNS record. The presence of a random value or
     * request token in the record is then verified to confirm control over the domain.
     */
    BR_3_2_2_4_7("3.2.2.4.7"),

    /**
     * Email to DNS Txt Contact.
     * <p>
     * This method involves sending an email to an address specified in a DNS TXT record. The DNS TXT record must be
     * located at _validation-contactemail.&lt;domain&gt;. The email will contain a random value that the recipient
     * can use to confirm control over the domain.
     */
    BR_3_2_2_4_14("3.2.2.4.14"),

    /**
     * Agreed-Upon Change to Website v2.
     * <p>
     * This method requires the domain owner to place a random value or request token in a specific file at a
     * predetermined location on their web server. The presence of this file containing the given random value or
     * request token confirms control over the FQDN.
     */
    BR_3_2_2_4_18("3.2.2.4.18");

    /** The DCV method string.
     */
    private final String brMethod;

    /**
     * Constructs a new DcvMethod with the specified DCV method string.
     *
     * @param brMethod the DCV method string
     */
    DcvMethod(String brMethod) {
        this.brMethod = brMethod;
    }
}