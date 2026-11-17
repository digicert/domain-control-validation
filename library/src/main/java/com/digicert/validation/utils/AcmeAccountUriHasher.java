package com.digicert.validation.utils;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Computes the hashed {@code accounturi} value used by the ACME {@code dns-persist-01} challenge
 * (BR 3.2.2.4.22 overlaid with IETF draft {@code draft-ietf-acme-dns-persist-02}, Section 4.1).
 * <p>
 * The {@code accounturi} value published in DNS is the CA's {@code accountHashPrefix}, the {@code sha-256}
 * hash-algorithm identifier, a "/" separator, and a base64url (unpadded) hash value. This class computes
 * only that final hash value (callers compare it against the tail of the published value and check the
 * prefix themselves). The hash value is the base64url encoding of:
 * <pre>
 *     SHA-256(length_of_domain || domain_name || key || account_URL)
 * </pre>
 * where {@code length_of_domain} is a single octet giving the length of {@code domain_name} in octets,
 * {@code domain_name} is either the exact validated FQDN or the single-octet {@code *} opt-out form, {@code key}
 * is the 43-character unpadded base64url RFC 7638 SHA-256 JWK Thumbprint, and {@code account_URL} is the
 * RFC 8555 account URL. All inputs are encoded as US-ASCII/UTF-8 octets, consistent with the draft's
 * requirement that the domain name, thumbprint, and account URL are all US-ASCII strings.
 * <p>
 * This class only supports the {@code sha-256} algorithm identifier form, which both clients and CAs are
 * required to support per the draft; it does not implement algorithm negotiation for other hash algorithms.
 */
public final class AcmeAccountUriHasher {

    /** The single-octet domain-independent opt-out form of {@code domain_name} (Section 4.1). */
    private static final String WILDCARD_OPT_OUT_DOMAIN = "*";

    /** The hash-algorithm identifier used in the hashed URI, per the draft's mandatory-to-implement algorithm. */
    public static final String HASH_ALGORITHM_IDENTIFIER = "sha-256";

    /** The digest algorithm name for {@link MessageDigest}, corresponding to {@link #HASH_ALGORITHM_IDENTIFIER}. */
    private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-256";

    /** Domain names are limited to 255 octets (RFC 1035, Section 2.3.4), so the length prefix is always one octet. */
    private static final int MAX_DOMAIN_OCTETS = 255;

    private AcmeAccountUriHasher() {
    }

    /**
     * Computes the base64url hash value for the exact validated domain name.
     * <p>
     * This method trusts its caller to have already validated {@code thumbprint} and {@code accountUrl}
     * (e.g. {@code AcmePersistentValueHandler.verifyRequest}); it performs no input validation of its own
     * beyond what is required to compute the hash (domain non-blank, domain length).
     *
     * @param domain the exact FQDN being validated, in normalized lowercase A-label form with no trailing dot
     * @param thumbprint the 43-character unpadded base64url RFC 7638 SHA-256 JWK Thumbprint of an account key
     * @param accountUrl the RFC 8555 ACME account URL
     * @return the unpadded base64url hash value
     * @throws IllegalArgumentException if the domain is null/blank, or exceeds 255 octets
     */
    public static String computeHash(String domain, String thumbprint, String accountUrl) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("domain cannot be null or blank");
        }

        byte[] domainBytes = domain.getBytes(StandardCharsets.US_ASCII);
        if (domainBytes.length > MAX_DOMAIN_OCTETS) {
            throw new IllegalArgumentException("domain cannot exceed " + MAX_DOMAIN_OCTETS + " octets");
        }

        return buildHash(domainBytes, thumbprint, accountUrl);
    }

    /**
     * Computes the base64url hash value for the domain-independent {@code *} opt-out form.
     * <p>
     * The resulting hash does not depend on the domain and may be reused across domains. This method
     * trusts its caller to have already validated {@code thumbprint} and {@code accountUrl}.
     *
     * @param thumbprint the 43-character unpadded base64url RFC 7638 SHA-256 JWK Thumbprint of an account key
     * @param accountUrl the RFC 8555 ACME account URL
     * @return the unpadded base64url hash value computed with {@code domain_name} set to the single octet {@code *}
     */
    public static String computeWildcardOptOutHash(String thumbprint, String accountUrl) {
        byte[] domainBytes = WILDCARD_OPT_OUT_DOMAIN.getBytes(StandardCharsets.US_ASCII);
        return buildHash(domainBytes, thumbprint, accountUrl);
    }

    private static String buildHash(byte[] domainBytes, String thumbprint, String accountUrl) {
        byte[] lengthOfDomain = new byte[]{(byte) domainBytes.length};
        byte[] keyBytes = thumbprint.getBytes(StandardCharsets.US_ASCII);
        byte[] accountUrlBytes = accountUrl.getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream input = new ByteArrayOutputStream(
                lengthOfDomain.length + domainBytes.length + keyBytes.length + accountUrlBytes.length);
        input.writeBytes(lengthOfDomain);
        input.writeBytes(domainBytes);
        input.writeBytes(keyBytes);
        input.writeBytes(accountUrlBytes);

        return digestToBase64Url(input.toByteArray());
    }

    private static String digestToBase64Url(byte[] input) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
            byte[] digest = messageDigest.digest(input);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every JDK; this should never happen.
            throw new IllegalStateException("SHA-256 message digest algorithm is unavailable", e);
        }
    }
}
