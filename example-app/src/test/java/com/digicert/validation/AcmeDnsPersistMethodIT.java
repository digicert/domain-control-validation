package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.client.PdnsClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.repository.DomainsRepository;
import com.digicert.validation.repository.entity.DomainEntity;
import com.digicert.validation.utils.DomainUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatusCode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end acceptance tests for the ACME {@code acme-dns-persist-01} DCV method (BR 3.2.2.4.22 overlaid
 * with draft-ietf-acme-dns-persist-02), driven through the example app's REST API against PowerDNS.
 * <p>
 * The expected {@code accounturi} hash is computed here by an independent implementation of the draft's
 * construction (not the library's hasher), so these tests also act as a cross-check of the library.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AcmeDnsPersistMethodIT {

    private static final String ISSUER_DOMAIN = "authority.example";
    // Must match the prefix configured in ExampleDCVConfiguration.
    private static final String CONFIGURED_PREFIX = "https://authority.example/account-hash/";
    private static final String UNCONFIGURED_PREFIX = "https://other-authority.example/account-hash/";
    private static final String PERSIST_LABEL = "_validation-persist";
    private static final long ACCOUNT_ID = 5432L;

    @Autowired
    private ExampleAppClient exampleAppClient;
    @Autowired
    private DomainsRepository domainsRepository;
    @Autowired
    private ObjectMapper objectMapper;
    private final PdnsClient pdnsClient = new PdnsClient();

    // ---- Happy paths ----

    @Test
    @DisplayName("ACME-PERSIST-IT-01: exact-domain hash validates and surfaces evidence")
    void validate_exactDomainHash_succeedsAndSurfacesEvidence() throws JsonProcessingException {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();
        long persistUntil = Instant.now().plusSeconds(7200).getEpochSecond();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri), "persistUntil=" + persistUntil));

        exampleAppClient.validateDomain(validateRequest(domainName, accountUri, List.of(thumbprint)), domain.getId());

        assertEquals(DcvRequestStatus.VALID, exampleAppClient.getDomainResource(domain.getId()).getStatus());
        Map<String, Object> response = acmePersistentTxtResponse(domain.getId());
        assertEquals(thumbprint, response.get("matchedThumbprint"));
        assertEquals(false, response.get("matchedWildcardOptOut"));
        assertEquals(ISSUER_DOMAIN, response.get("matchedIssuerDomain"));
        assertEquals(false, response.get("policyWildcard"));
        assertEquals(persistUntil, ((Number) response.get("persistUntil")).longValue());
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-02: wildcard opt-out hash with policy=wildcard validates and surfaces the policy")
    void validate_wildcardOptOutHashWithPolicyWildcard_succeeds() throws JsonProcessingException {
        String domainName = DomainUtils.getRandomDomainName(2, "net");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash("*", thumbprint, accountUri), "policy=wildcard"));

        exampleAppClient.validateDomain(validateRequest(domainName, accountUri, List.of(thumbprint)), domain.getId());

        Map<String, Object> response = acmePersistentTxtResponse(domain.getId());
        assertEquals(true, response.get("matchedWildcardOptOut"));
        assertEquals(true, response.get("policyWildcard"));
        assertNull(response.get("persistUntil"));
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-03: record published under a historical thumbprint validates (thumbprint order is respected)")
    void validate_historicalThumbprintMatches_succeeds() throws JsonProcessingException {
        String domainName = DomainUtils.getRandomDomainName(2, "org");
        String accountUri = newAccountUri();
        String activeThumbprint = newThumbprint();
        String historicalThumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, historicalThumbprint, accountUri)));

        exampleAppClient.validateDomain(validateRequest(domainName, accountUri, List.of(activeThumbprint, historicalThumbprint)), domain.getId());

        assertEquals(historicalThumbprint, acmePersistentTxtResponse(domain.getId()).get("matchedThumbprint"));
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-04: only the record for an allowed issuer is used when several issuers have records")
    void validate_multipleIssuerRecords_usesAllowedIssuerRecord() throws JsonProcessingException {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        String otherIssuerRecord = issueValue("other-ca.example", CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri));
        String ourRecord = issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri));
        pdnsClient.addValueToRecord(domainName, List.of(otherIssuerRecord, ourRecord), PdnsClient.PdnsRecordType.TXT, PERSIST_LABEL);

        exampleAppClient.validateDomain(validateRequest(domainName, accountUri, List.of(thumbprint)), domain.getId());

        assertEquals(ISSUER_DOMAIN, acmePersistentTxtResponse(domain.getId()).get("matchedIssuerDomain"));
    }

    // ---- Failure paths ----

    @Test
    @DisplayName("ACME-PERSIST-IT-05: account URI not owned by the account is rejected")
    void validate_accountUriNotOwnedByAccount_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String ownedAccountUri = newAccountUri();
        String unownedAccountUri = ownedAccountUri + "-other";
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, ownedAccountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, thumbprint, unownedAccountUri)));

        assertRejectedAndStillPending(validateRequest(domainName, unownedAccountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-06: hash for a thumbprint that was not supplied is rejected")
    void validate_unknownThumbprint_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, newThumbprint(), accountUri)));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(newThumbprint())), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-07: record for an issuer that is not allowed is rejected")
    void validate_issuerNotAllowed_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue("not-allowed.example", CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri)));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-08: record whose persistUntil has passed is rejected")
    void validate_persistUntilExpired_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        long expired = Instant.now().minusSeconds(3600).getEpochSecond();
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri), "persistUntil=" + expired));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-09: missing TXT record is rejected")
    void validate_noTxtRecord_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();

        DomainResource domain = submitDomain(domainName, accountUri);
        // Zone exists but has no _validation-persist record.
        pdnsClient.createLocalhostARecord(domainName);

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(newThumbprint())), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-10: hash published under an unconfigured account-hash prefix is rejected")
    void validate_unconfiguredAccountHashPrefix_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, UNCONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri)));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-11: record with more than one accounturi is rejected even if one matches")
    void validate_multipleAccountUris_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        String matching = CONFIGURED_PREFIX + "sha-256/" + hash(domainName, thumbprint, accountUri);
        String other = CONFIGURED_PREFIX + "sha-256/" + hash(domainName, newThumbprint(), accountUri);
        pdnsClient.addPersistentTxtValue(domainName, ISSUER_DOMAIN + "; accounturi=" + matching + "; accounturi=" + other);

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-12: malformed thumbprint is rejected")
    void validate_malformedThumbprint_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, newThumbprint(), accountUri)));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of("not-a-valid-thumbprint")), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-13: record with more than one policy parameter is rejected")
    void validate_duplicatePolicyParameter_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                issueValue(ISSUER_DOMAIN, CONFIGURED_PREFIX, hash(domainName, thumbprint, accountUri), "policy=wildcard", "policy=wildcard"));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    @Test
    @DisplayName("ACME-PERSIST-IT-14: accounturi with an unsupported hash algorithm is rejected as malformed")
    void validate_unsupportedHashAlgorithm_isRejected() {
        String domainName = DomainUtils.getRandomDomainName(2, "com");
        String accountUri = newAccountUri();
        String thumbprint = newThumbprint();

        DomainResource domain = submitDomain(domainName, accountUri);
        pdnsClient.addPersistentTxtValue(domainName,
                ISSUER_DOMAIN + "; accounturi=" + CONFIGURED_PREFIX + "sha-512/" + hash(domainName, thumbprint, accountUri));

        assertRejectedAndStillPending(validateRequest(domainName, accountUri, List.of(thumbprint)), domain);
    }

    // ---- Helpers ----

    private void assertRejectedAndStillPending(ValidateRequest validateRequest, DomainResource domain) {
        HttpStatusCode status = exampleAppClient.validateDomainExpectingFailure(validateRequest, domain.getId());
        assertTrue(status.is4xxClientError(), "expected a 4xx response but got " + status);
        assertEquals(DcvRequestStatus.PENDING, exampleAppClient.getDomainResource(domain.getId()).getStatus());
        DomainEntity entity = domainsRepository.findById(domain.getId()).orElseThrow();
        assertNull(entity.getValidationEvidence(), "no validation evidence should be stored for a rejected validation");
    }

    private DomainResource submitDomain(String domainName, String accountUri) {
        exampleAppClient.submitAccountUri(ACCOUNT_ID, accountUri);
        DcvRequest dcvRequest = new DcvRequest(domainName, null, accountUri, ACCOUNT_ID, DcvRequestType.ACME_DNS_PERSIST);
        DomainResource created = exampleAppClient.submitDnsDomain(dcvRequest);
        assertEquals(DcvRequestType.ACME_DNS_PERSIST, created.getDcvType());
        assertEquals(DcvRequestStatus.PENDING, created.getStatus());
        return created;
    }

    private static ValidateRequest validateRequest(String domainName, String accountUri, List<String> thumbprints) {
        return ValidateRequest.builder()
                .domain(domainName)
                .dcvRequestType(DcvRequestType.ACME_DNS_PERSIST)
                .accountUri(accountUri)
                .accountThumbprints(thumbprints)
                .build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> acmePersistentTxtResponse(long domainId) throws JsonProcessingException {
        DomainEntity entity = domainsRepository.findById(domainId).orElseThrow();
        assertNotNull(entity.getValidationEvidence());
        Map<String, Object> evidence = objectMapper.readValue(entity.getValidationEvidence(), Map.class);
        Map<String, Object> response = (Map<String, Object>) evidence.get("acmePersistentTxtResponse");
        assertNotNull(response, "evidence should contain acmePersistentTxtResponse");
        assertFalse(response.isEmpty());
        return response;
    }

    private static String issueValue(String issuer, String prefix, String hash, String... extraParameters) {
        StringBuilder value = new StringBuilder(issuer)
                .append("; accounturi=").append(prefix).append("sha-256/").append(hash);
        for (String extra : extraParameters) {
            value.append("; ").append(extra);
        }
        return value.toString();
    }

    private static String newAccountUri() {
        return "https://acme.authority.example/acct/" + System.nanoTime();
    }

    /** A random, correctly shaped (43 char unpadded base64url) RFC 7638 SHA-256 JWK thumbprint. */
    private static String newThumbprint() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Independent implementation of draft-ietf-acme-dns-persist-02 Section 4.1:
     * base64url(SHA-256(len(domain) || domain || key || account_URL)), no padding.
     */
    private static String hash(String domainName, String thumbprint, String accountUri) {
        try {
            byte[] domain = domainName.getBytes(StandardCharsets.US_ASCII);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((byte) domain.length);
            digest.update(domain);
            digest.update(thumbprint.getBytes(StandardCharsets.US_ASCII));
            digest.update(accountUri.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
