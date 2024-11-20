package com.digicert.validation.enums;

/**
 * This enum represents the options for types of information that can be used for domain control validation challenges.
 * A random value is provided by the CA to the domain owner, and a request token is a value generated by the
 * domain owner according to the CA's specifications.
 */
public enum ChallengeType {

    /**
     * Specify that the domain control validation method will use a random value.
     * <p>
     * Random values are required to have at least 112 bits of entropy, and will be generated by the CA and provided to
     * the domain owner. For email domain control validation methods, the value is sent to the domain owner via email
     * and knowledge of the random value is sufficient to prove control over the domain. For other domain control
     * validation methods, the random value must be placed in a specific location (either a DNS record or a file on the
     * web server) to prove control.
     * </p>
     */
    RANDOM_VALUE,

    /**
     * Specify that the domain control validation method will expect a request token.
     * <p>
     * A request token is a domain owner&ndash;generated token that is generated according to a format specified by the
     * CA. Each request token must incorporate the key used in the certificate request and can only be reused if the
     * token includes a timestamp. The request token must be placed in a specific location (either a DNS record or a
     * file on the web server) to prove control. Request tokens cannot be used for email domain control validation
     * methods.
     * </p>
     * <p>
     * It is useful to note that because request tokens are not supplied by the CA, it is possible to skip the
     * preparation step when using request tokens.
     * </p>
     */
    REQUEST_TOKEN
}