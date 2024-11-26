package com.digicert.validation.methods.file.prepare;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.enums.ChallengeType;

/**
 * Represents a request for file validation preparation.
 * <p>
 * This class encapsulates the details required to prepare for file validation. File validation is a method used to
 * verify the ownership or control of a domain by placing a specific file at a predetermined location on the domain's
 * web server. The FilePreparationRequest class includes the domain for which the authentication is being prepared, the
 * type of challenge used for validation, and an optional filename if the default will not be used.
 *
 * @param domain the domain for which the file validation preparation is requested
 *               <p>
 *               This field specifies the domain name that is the subject of the file validation request. The domain name
 *               must be a valid fully qualified domain name (FQDN).
 * @param filename the filename where the challenge value will be stored and queried on the server
 *                 <p>
 *                 This field specifies the filename where the challenge value will be stored and queried on the server.
 *                 The file must be placed in the /.well-known/pki-validation/ directory of the domain's web server.
 *                 This field is optional, and will default to the value configured in {@link DcvConfiguration} if
 *                 not provided.
 * @param challengeType the type of challenge to use for validation
 *                      <p>
 *                      This field indicates the type of challenge that will be used in the file validation process. The
 *                      challenge type is either RANDOM_VALUE or REQUEST_TOKEN. The RANDOM_VALUE challenge type requires
 *                      the customer to use a CA-generated random value, while the REQUEST_TOKEN challenge type requires
 *                      the customer to use a request token generated themselves according to the CA's specifications.
 */
public record FilePreparationRequest(String domain, String filename, ChallengeType challengeType) {

    /**
     * Constructs a new FilePreparationRequest with the specified domain and a default challenge type of RANDOM_VALUE.
     * <p>
     * This constructor initializes a new instance of FilePreparationRequest using the provided domain name and sets the
     * challenge type to RANDOM_VALUE by default. Using the REQUEST_TOKEN challenge type does not require any
     * domain-specific data, so calling prepare for a domain name using RANDOM_VALUE is the most common use case for
     * file validation preparation.
     *
     * @param domain the domain for which the file validation preparation is requested
     * <p>
     * This field specifies the domain name that is the subject of the file validation request. The domain name
     * must be a valid fully qualified domain name (FQDN).
     */
    public FilePreparationRequest(String domain) {
        this(domain, null, ChallengeType.RANDOM_VALUE);
    }
}