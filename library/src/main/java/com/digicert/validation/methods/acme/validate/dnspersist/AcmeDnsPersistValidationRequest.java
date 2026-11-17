package com.digicert.validation.methods.acme.validate.dnspersist;

import com.digicert.validation.common.ValidationState;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a request to validate the ACME {@code acme-dns-persist-01} persistent DNS TXT challenge
 * (BR 3.2.2.4.22 overlaid with IETF draft {@code draft-ietf-acme-dns-persist-02}).
 * <p>
 * This is a dedicated request type for this method, distinct from both {@code AcmeValidationRequest}
 * (the ephemeral {@code ACME_DNS_01}/{@code ACME_HTTP_01} flow, which requires a random value and checks
 * its lifetime&mdash;neither of which applies here) and {@code DnsValidationRequest} (the generic DNS
 * request shape used by {@code DnsValidator}). This class is immutable and uses the builder pattern.
 */
@Getter
@Builder
@ToString
public class AcmeDnsPersistValidationRequest {

    /** The domain to be validated. */
    private final String domain;

    /**
     * The raw (un-hashed) ACME account URL (RFC 8555 Section 7.3).
     * <p>
     * This field reuses the name {@code accountUri} intentionally, mirroring the non-ACME persistent-value
     * method's field of the same name. The two serve a parallel purpose (identifying the ACME account to
     * the persistent-value mechanism) even though their contents differ in shape: here it is the raw,
     * un-hashed account URL that this library hashes itself (per {@link com.digicert.validation.utils.AcmeAccountUriHasher}); the
     * non-ACME method's {@code accountUri} is instead an already-formed value compared directly. Because
     * this class is a separate, dedicated request type (not shared with the non-ACME method's request
     * object), there is no risk of the two being confused on the same request instance.
     */
    private final String accountUri;

    /**
     * The list of account-key thumbprints (RFC 7638 SHA-256 JWK thumbprints, base64url, unpadded) to try
     * when computing/matching the hashed {@code accounturi}: the active/current key, and optionally one or
     * more historical/prior keys. The library computes and compares the hashed {@code accounturi} itself
     * for every supplied thumbprint, for both the exact validated domain name and the domain-independent
     * {@code *} opt-out form.
     */
    private final List<String> accountThumbprints;

    /** The current state of the validation process. */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain The domain to be validated.
     * @param accountUri The raw ACME account URL.
     * @param accountThumbprints The list of account-key thumbprints.
     * @param validationState The current validation state.
     */
    private AcmeDnsPersistValidationRequest(String domain,
                                            String accountUri,
                                            List<String> accountThumbprints,
                                            ValidationState validationState) {
        this.domain = domain;
        this.accountUri = accountUri;
        // Defensive, unmodifiable copy (null entries are preserved so verifyRequest can still report them).
        this.accountThumbprints = accountThumbprints == null ? null : Collections.unmodifiableList(new ArrayList<>(accountThumbprints));
        this.validationState = validationState;
    }
}
