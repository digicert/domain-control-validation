package com.digicert.validation.methods.acme.validate.dnspersist;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.dnspersist.AcmePersistentValueHandler.CandidateHash;
import com.digicert.validation.methods.acme.validate.dnspersist.AcmePersistentValueHandler.MatchResult;
import com.digicert.validation.utils.issueValue.ParsedIssueValue;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Shows how {@link AcmePersistentValueHandler#selectMostValid} chooses which record's errors are reported when
 * none of the records is valid. The test repeatedly takes the record reported as most valid, removes it, and
 * checks that the order from most to least valid is the one we expect.
 */
class AcmePersistentValueHandlerRecordSelectionTest {

    private static final CandidateHash MATCHED = new CandidateHash("thumbprint", "https://ca.example/account-hash/", false, "uri");

    @Test
    void selectMostValid_ordersRecordsFromMostToLeastValid() {
        // Deliberately not in the expected order. Records with the same rank keep their input order.
        List<MatchResult> remaining = new ArrayList<>(List.of(
                record("otherCaRecord", false, DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED, DcvError.INVALID_ISSUE_VALUE_FORMAT),
                record("wrongHashOurIssuer", false, DcvError.ACCOUNT_URI_MISMATCH),
                record("duplicatePolicy", true, DcvError.MULTIPLE_POLICY),
                record("malformedOurIssuer", false, DcvError.INVALID_ISSUE_VALUE_FORMAT),
                record("multipleAccountUris", true, DcvError.MULTIPLE_ACCOUNT_URI, DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED),
                record("issuerTypoValidHash", true, DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED),
                record("expiredPersistUntil", true, DcvError.PERSISTENT_RECORD_EXPIRED)));

        List<String> mostToLeastValid = new ArrayList<>();
        while (!remaining.isEmpty()) {
            MatchResult best = AcmePersistentValueHandler.selectMostValid(remaining);
            mostToLeastValid.add(best.parsedIssueValue().issuerDomainName());
            remaining.removeIf(result -> result == best);
        }

        assertEquals(List.of(
                // hash matched, only persistUntil or a repeated policy is wrong
                "duplicatePolicy",
                "expiredPersistUntil",
                // hash matched but the issuer is not allowed (e.g. a typo in the issuer name)
                "issuerTypoValidHash",
                // our issuer, accounturi malformed
                "malformedOurIssuer",
                // our issuer, well-formed accounturi with the wrong hash
                "wrongHashOurIssuer",
                // everything else, including another CA's record that never matched
                "otherCaRecord",
                "multipleAccountUris"), mostToLeastValid);
    }

    @Test
    void selectMostValid_anotherCasRecordDoesNotHideOurWrongHash() {
        MatchResult otherCa = record("otherCaRecord", false, DcvError.ISSUER_DOMAIN_NAME_NOT_ALLOWED, DcvError.INVALID_ISSUE_VALUE_FORMAT);
        MatchResult ours = record("wrongHashOurIssuer", false, DcvError.ACCOUNT_URI_MISMATCH);

        assertEquals(ours, AcmePersistentValueHandler.selectMostValid(List.of(otherCa, ours)));
        assertEquals(ours, AcmePersistentValueHandler.selectMostValid(List.of(ours, otherCa)));
    }

    @Test
    void selectMostValid_noRecords_returnsNull() {
        assertNull(AcmePersistentValueHandler.selectMostValid(List.of()));
    }

    /** Builds a record result; the issuer name is only used as a label for the assertions. */
    private static MatchResult record(String label, boolean hashMatched, DcvError... errors) {
        ParsedIssueValue issueValue = new ParsedIssueValue(label, new LinkedHashMap<>());
        issueValue.addDcvErrors(Set.of(errors));
        return new MatchResult(hashMatched ? MATCHED : null, issueValue);
    }
}
