package com.digicert.validation.methods.file.prepare;

import com.digicert.validation.enums.ChallengeType;

/**
 * Represents a request for file validation preparation.
 * <p>
 * This class encapsulates the details required to prepare for file validation. File validation is a method used to
 * verify the ownership or control of a domain by placing a specific file at a predetermined location on the domain's web server.
 * The FilePreparationRequest class includes the domain for which the authentication is being prepared and the type of secret
 * used for validation. The secret type can vary, providing flexibility in the validation process.
 *
 * @param domain the domain for which the file validation preparation is requested
 *               <p>
 *               This field specifies the domain name that is the subject of the file validation request. The domain name
 *               must be a valid and fully qualified domain name (FQDN). It is essential for identifying the target domain where
 *               the authentication file will be placed. Accurate specification of the domain ensures that the validation process
 *               is correctly targeted.
 * @param filename the filename where the challenge value will be stored and queried on the server
 *                   <p>
 *                    This field specifies the filename where the challenge value will be stored and queried on the server.
 *                    The file must be placed in the /.well-known/pki-validation/ directory of the domain's web server.
 *                    This field is optional, and will default to 'fileauth.txt' if not provided.
 * @param challengeType the type of secret used for validation
 *                   <p>
 *                   This field indicates the type of secret that will be used in the file validation process. The secret type
 *                   can be a predefined value such as RANDOM_VALUE, which is a randomly generated value used to ensure the
 *                   uniqueness and security of the validation process. The choice of secret type can affect the complexity and
 *                   security of the authentication.
 */
public record FilePreparationRequest(String domain, String filename, ChallengeType challengeType) {

    /**
     * Constructs a new FilePreparationRequest with the specified domain and a default challenge type of RANDOM_VALUE.
     * <p>
     * This constructor initializes a new instance of FilePreparationRequest using the provided domain name and sets the
     * secret type to RANDOM_VALUE by default. This is useful for scenarios where a random value is sufficient for the validation
     * process, simplifying the creation of the request by not requiring the caller to specify the secret type explicitly.
     *
     * @param domain the domain for which the file validation preparation is requested
     *               <p>
     *               This parameter specifies the domain name that will be used in the file validation process. It must be a
     *               valid domain name, ensuring that the request is correctly targeted.
     */
    public FilePreparationRequest(String domain) {
        this(domain, null, ChallengeType.RANDOM_VALUE);
    }
}