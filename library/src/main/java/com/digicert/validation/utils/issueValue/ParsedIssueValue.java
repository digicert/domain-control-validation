package com.digicert.validation.utils.issueValue;

import com.digicert.validation.enums.DcvError;
import lombok.Builder;

import java.util.*;

/**
 * Represents the result of parsing a CAA issue-value string.
 * Contains the parsed issuer domain name, parameters, any parsing exception, and accumulated DCV errors.
 *
 * @param issuerDomainName the parsed issuer domain name, or {@code null} if absent or invalid
 * @param parameters       the parsed tag-to-value parameter map
 * @param parseException   the parsing exception if parsing failed, or {@code null} if successful
 * @param dcvErrors        the set of DCV errors accumulated during parsing and validation
 */
@Builder
public record ParsedIssueValue(String issuerDomainName,
                               Map<String, List<String>> parameters,
                               IssueValueParser.IssueValueParsingException parseException,
                               Set<DcvError> dcvErrors) {

    /**
     * Canonical constructor that normalizes null collections and seeds DCV errors from any parse exception.
     *
     * @param issuerDomainName the parsed issuer domain name, or {@code null} if absent or invalid
     * @param parameters       the parsed tag-to-value parameter map; normalized to an empty map if null
     * @param parseException   the parsing exception if parsing failed, or {@code null} if successful
     * @param dcvErrors        the initial set of DCV errors; normalized to an empty set if null
     */
    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters, IssueValueParser.IssueValueParsingException parseException, Set<DcvError> dcvErrors) {
        this.issuerDomainName = issuerDomainName;
        this.parameters = parameters == null ? new HashMap<>() : parameters;
        this.parseException = parseException;
        this.dcvErrors = dcvErrors == null ? new HashSet<>() : dcvErrors;
        if (this.parseException != null) {
            this.dcvErrors.add(this.parseException.getDcvError());
        }
    }

    /**
     * Convenience constructor for a failed parse result with no initial DCV errors.
     *
     * @param issuerDomainName the parsed issuer domain name, or {@code null} if absent or invalid
     * @param parameters       the parsed tag-to-value parameter map
     * @param parseException   the parsing exception describing the failure
     */
    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters, IssueValueParser.IssueValueParsingException parseException) {
        this(issuerDomainName, parameters, parseException, new HashSet<>());
    }

    /**
     * Convenience constructor for a successful parse result with no errors.
     *
     * @param issuerDomainName the parsed issuer domain name
     * @param parameters       the parsed tag-to-value parameter map
     */
    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters) {
        this(issuerDomainName, parameters, null, new HashSet<>());
    }

    /**
     * Adds additional DCV errors to this parsed result.
     *
     * @param parsedRecordErrors the set of DCV errors to add
     */
    public void addDcvErrors(Set<DcvError> parsedRecordErrors) {
        this.dcvErrors.addAll(parsedRecordErrors);
    }
}
