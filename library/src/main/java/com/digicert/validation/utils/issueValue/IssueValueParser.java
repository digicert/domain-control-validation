package com.digicert.validation.utils.issueValue;

import com.digicert.validation.enums.DcvError;
import lombok.Getter;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Parser for issue-value property values.
 * Parsing behavior notes relative to RFC 8659 section 4.2:
 *  - Any surrounding double quotes, such as those required for properly formatted TXT records, will be stripped before parsing.
 *  - All whitespace around components will be trimmed.
 *  - issuer-domain-name and parameter tags are validated as LDH labels (letter-digit-hyphen, with no leading/trailing hyphen).
 *  - Parameter values are validated to RFC ABNF character ranges: %x21-3A / %x3C-7E.
 *  - Malformed parameter segments (for example, missing '=' or empty segments) cause a parsing error.
 *  - Parsing never throws; failures are returned on the ParsedIssueValue.parseException field and ParsedIssueValue.isValid() is false.
 *
 * <p>Syntax reference:
 * "The RDATA value MUST conform to the issue-value syntax as defined in RFC 8659, Section 4.2;"
 * <a href="https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.2.6.pdf"> BR-2.2.6 page 37</a>.
 * <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-4.2">RFC 8659, section 4.2</a>.
 * ABNF core rules come from <a href="https://datatracker.ietf.org/doc/html/rfc5234">RFC 5234</a>.
 */
public final class IssueValueParser {
    private static final Pattern LDH_LABEL_PATTERN = Pattern.compile("[A-Za-z0-9](?:-*[A-Za-z0-9])*");
    // RFC 8659 section 4.2 value charset: %x21-3A / %x3C-7E (printable ASCII except space and ';').
    private static final Pattern ISSUE_VALUE_CHARSET_PATTERN = Pattern.compile("[\\x21-\\x3A\\x3C-\\x7E]*");

    private IssueValueParser() {
    }

    public static ParsedIssueValue parse(String input) {
        String issuerDomainName = null;
        try {
            if (input == null) {
                return new ParsedIssueValue(null, new LinkedHashMap<>(),
                        new IssueValueParsingException(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND, "issue-value must not be null"));
            }

            String normalizedInput = trimWhitespaceAndStripQuotes(input);
            String[] issuerDomainNameAndRest = normalizedInput.split(";", 2);
            issuerDomainName = issuerDomainNameAndRest[0].strip();
            IssueValueParsingException issuerValidationError = checkConformsToLetterDashHyphen(issuerDomainName);
            if (issuerValidationError != null) {
                return new ParsedIssueValue(issuerDomainName, new LinkedHashMap<>(), issuerValidationError);
            }

            if (issuerDomainNameAndRest.length == 1) {
                return new ParsedIssueValue(issuerDomainName, new LinkedHashMap<>());
            }

            String[] rest = issuerDomainNameAndRest[1].split(";", -1); //-1 will not discard a trailing empty string, which should be reported as invalid
            List<Pair<String, String>> parsed = Arrays.stream(rest)
                                                        .map(String::strip)
                                                        .map(IssueValueParser::parseParameter)
                                                        .toList();
            Map<String, List<String>> parsedParameters = new LinkedHashMap<>();
            parsed.forEach(parsedKeyValue -> parsedParameters.computeIfAbsent(parsedKeyValue.getLeft(), k -> new ArrayList<>()).add(parsedKeyValue.getRight()));
            return new ParsedIssueValue(issuerDomainName, parsedParameters);
        } catch (IssueValueParsingException e) {
            return new ParsedIssueValue(issuerDomainName, new LinkedHashMap<>(), e);
        }
    }

    private static Pair<String, String> parseParameter(String s) {
        if (s.isEmpty()) {
            throw parseError("empty parameter segment");
        }
        String[] tagAndValue = s.split("=", 2);
        if (tagAndValue.length != 2) {
            throw parseError("parameter must contain '='");
        }

        String tag = tagAndValue[0].strip();
        String value = tagAndValue[1].strip();

        validateTag(tag);
        validateValue(value);
        return Pair.of(tag, value);
    }

    private static IssueValueParsingException checkConformsToLetterDashHyphen(String issuerDomainName) {
        if (issuerDomainName == null || issuerDomainName.isEmpty()) {
            return null;
        }

        String[] labels = issuerDomainName.split("\\.", -1);
        for (String label : labels) {
            if (!LDH_LABEL_PATTERN.matcher(label).matches()) {
                return parseError("issuer-domain-name contains invalid characters");
            }
        }
        return null;
    }

    private static void validateTag(String tag) {
        if (!LDH_LABEL_PATTERN.matcher(tag).matches()) {
            throw parseError("parameter tag contains invalid characters");
        }
    }

    private static void validateValue(String value) {
        if (!ISSUE_VALUE_CHARSET_PATTERN.matcher(value).matches()) {
            throw parseError("parameter value contains invalid characters");
        }
    }

    /*
     * Normalizes the input by removing whitespace and surrounding double quotes if they are present and balanced.
     */
    private static String trimWhitespaceAndStripQuotes(String input) {
        input = input.strip();
        boolean startsWith = input.startsWith("\"");
        boolean endsWith = input.endsWith("\"");
        if (startsWith && endsWith) {
            return input.substring(1, input.length() - 1).strip();
        } else if (startsWith) {
            throw parseError("unbalanced surrounding quote");
        }
        return input;
    }


    private static IssueValueParsingException parseError(String input) {
        return new IssueValueParsingException(DcvError.INVALID_ISSUE_VALUE_FORMAT,input);
    }

    @Getter
    public static class IssueValueParsingException extends RuntimeException {
        private final DcvError dcvError;

        public IssueValueParsingException(DcvError error,String message) {
            super(message);
            this.dcvError = error;
        }
    }
}
