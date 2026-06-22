package com.digicert.validation.utils.issueValue;

import com.digicert.validation.enums.DcvError;
import lombok.Builder;

import java.util.*;

@Builder
public record ParsedIssueValue(String issuerDomainName,
                               Map<String, List<String>> parameters,
                               IssueValueParser.IssueValueParsingException parseException,
                               Set<DcvError> dcvErrors) {

    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters, IssueValueParser.IssueValueParsingException parseException, Set<DcvError> dcvErrors) {
        this.issuerDomainName = issuerDomainName;
        this.parameters = parameters == null ? new HashMap<>() : parameters;
        this.parseException = parseException;
        this.dcvErrors = dcvErrors == null ? new HashSet<>() : dcvErrors;
        if (this.parseException != null) {
            this.dcvErrors.add(this.parseException.getDcvError());
        }
    }

    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters, IssueValueParser.IssueValueParsingException parseException) {
        this(issuerDomainName, parameters, parseException, new HashSet<>());
    }

    public ParsedIssueValue(String issuerDomainName, Map<String, List<String>> parameters) {
        this(issuerDomainName, parameters, null, new HashSet<>());
    }

    public void addDcvErrors(Set<DcvError> parsedRecordErrors) {
        this.dcvErrors.addAll(parsedRecordErrors);
    }
}
