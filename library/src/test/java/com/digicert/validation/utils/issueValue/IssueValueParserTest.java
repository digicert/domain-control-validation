package com.digicert.validation.utils.issueValue;

import com.digicert.validation.enums.DcvError;
import lombok.Builder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class IssueValueParserTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("validCases")
    void parse_validCases(String description, ValidCase validCase) {
        ParsedIssueValue parsed = IssueValueParser.parse(validCase.input());

        assertTrue(parsed.dcvErrors().isEmpty());
        assertNull(parsed.parseException());
        assertEquals(validCase.expected().issuerDomainName(), parsed.issuerDomainName());
        assertEquals(validCase.expected().parameters(), parsed.parameters());
        assertNotNull(parsed.parameters());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidCases")
    void parse_invalidCases(String description, InvalidCase invalidCase) {
        ParsedIssueValue parsed = IssueValueParser.parse(invalidCase.input());

        assertFalse(parsed.dcvErrors().isEmpty());
        assertNotNull(parsed.parseException());
        assertEquals(invalidCase.expectedDcvError(), parsed.parseException().getDcvError());
        assertNotNull(parsed.parameters());
    }

    private static Stream<Arguments> validCases() {
        return Stream.of(
                Arguments.of("issuer only", valid().input("example.org").expected(new ParsedIssueValue("example.org", Map.of())).build()),
                Arguments.of("issuer with accounturi and persistuntil", valid().input("  authority.example ; accounturi = https://authority.example/acct/123\t;\tpersistuntil=4102444800")
                                                                                .expected(new ParsedIssueValue("authority.example", Map.ofEntries(
                                                                                        Map.entry("accounturi", List.of("https://authority.example/acct/123")),
                                                                                        Map.entry("persistuntil", List.of("4102444800"))))).build()),
                Arguments.of("quoted issuer with two parameters", valid().input("\"authority.example; accounturi=https://authority.example/acct/1; persistuntil=4102444800\"")
                                                                          .expected(new ParsedIssueValue("authority.example", Map.ofEntries(
                                                                                  Map.entry("accounturi", List.of("https://authority.example/acct/1")),
                                                                                  Map.entry("persistuntil", List.of("4102444800"))))).build()),
                Arguments.of("quoted issuer with outer whitespace", valid().input("  \"authority.example; accounturi=https://authority.example/acct/1\"\t")
                                                                            .expected(new ParsedIssueValue("authority.example", Map.of("accounturi", List.of("https://authority.example/acct/1")))).build()),
                Arguments.of("missing issuer with accounturi", valid().input(" ; accounturi=https://authority.example/acct/1")
                                                                       .expected(new ParsedIssueValue("", Map.of("accounturi", List.of("https://authority.example/acct/1")))).build()),
                Arguments.of("empty parameter value", valid().input("authority.example; a=; b=x")
                                                              .expected(new ParsedIssueValue("authority.example", Map.ofEntries(
                                                                      Map.entry("a", List.of("")),
                                                                      Map.entry("b", List.of("x"))))).build()),
                Arguments.of("value containing equals", valid().input("authority.example; A=b=c")
                                                                .expected(new ParsedIssueValue("authority.example", Map.of("A", List.of("b=c")))).build()),
                Arguments.of("ascii punctuation value", valid().input("authority.example; tag=!:<~=")
                                                                .expected(new ParsedIssueValue("authority.example", Map.of("tag", List.of("!:<~=")))).build()),
                Arguments.of("tabs around delimiter", valid().input("authority.example; a=1\t;\tb=2")
                                                              .expected(new ParsedIssueValue("authority.example", Map.ofEntries(
                                                                      Map.entry("a", List.of("1")),
                                                                      Map.entry("b", List.of("2"))))).build()),
                Arguments.of("duplicate accounturi values", valid().input("authority.example; accounturi=https://authority.example/a; accounturi=https://authority.example/b")
                                                                    .expected(new ParsedIssueValue("authority.example", Map.of("accounturi", List.of("https://authority.example/a", "https://authority.example/b")))).build()),
                Arguments.of("accounturi with persistuntil", valid().input("authority.example; accounturi=https://authority.example/a; persistuntil=4102444800")
                                                                     .expected(new ParsedIssueValue("authority.example", Map.ofEntries(
                                                                             Map.entry("accounturi", List.of("https://authority.example/a")),
                                                                             Map.entry("persistuntil", List.of("4102444800"))))).build()),
                Arguments.of("single accounturi parameter", valid().input("authority.example; accounturi=https://authority.example/a")
                                                                    .expected(new ParsedIssueValue("authority.example", Map.of("accounturi", List.of("https://authority.example/a")))).build()),
                Arguments.of("unbalanced closing quote", valid().input("authority.example; accounturi=https://authority.example/acct/1; param=\"quotedvalue\"")
                                                                 .expected(new ParsedIssueValue("authority.example", Map.of("accounturi", List.of("https://authority.example/acct/1"), "param", List.of("\"quotedvalue\"")))).build()));
    }

    private static Stream<Arguments> invalidCases() {
        return Stream.of(
                Arguments.of("null input", invalid().input(null).expectedDcvError(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND).build()),
                Arguments.of("missing parameter value", invalidFormat("authority.example; accounturi")),
                Arguments.of("invalid parameter format branch", invalidFormat("authority.example; accounturi; persistuntil=4102444800")),
                Arguments.of("empty parameter triggers parseParameter", invalidFormat("authority.example; accounturi=https://authority.example/acct/1;;persistuntil=4102444800")),
                Arguments.of("trailing semicolon", invalidFormat("authority.example; accounturi=https://authority.example/acct/1;")),
                Arguments.of("double semicolon", invalidFormat("authority.example;;accounturi=https://authority.example/acct/1")),
                Arguments.of("triple semicolon after issuer", invalidFormat("issuer.domain;;;")),
                Arguments.of("unbalanced opening quote", invalidFormat("\"authority.example; accounturi=https://authority.example/acct/1")),
                Arguments.of("semicolon only", invalidFormat(";")),
                Arguments.of("issuer with trailing semicolon only", invalidFormat("authority.example;")),
                Arguments.of("empty parameter segment", invalidFormat("authority.example; ; accounturi=https://authority.example/acct/1")),
                Arguments.of("trailing whitespace segment", invalidFormat("authority.example; accounturi=https://authority.example/acct/1;   ")),
                Arguments.of("issuer and empty segment only", invalidFormat("; ;"))
                ,Arguments.of("single-quoted issuer text", invalidFormat("'   '"))
                ,Arguments.of("invalid issuer-domain-name characters", invalidFormat("authority_1.example; accounturi=https://authority.example/acct/1"))
                ,Arguments.of("invalid tag characters", invalidFormat("authority.example; acc_ounturi=https://authority.example/acct/1"))
                ,Arguments.of("invalid value characters", invalidFormat("authority.example; accounturi=bad value"))
                , Arguments.of("null tag name", invalidFormat("authority.example; accounturi=https://authority.example/a; ="))
        );
    }

    private static ValidCase.ValidCaseBuilder valid() {
        return ValidCase.builder();
    }

    @Builder
    private record ValidCase(String input, ParsedIssueValue expected) {
    }

    private static InvalidCase.InvalidCaseBuilder invalid() {
        return InvalidCase.builder();
    }

    private static InvalidCase invalidFormat(String input) {
        return invalid().input(input).expectedDcvError(DcvError.INVALID_ISSUE_VALUE_FORMAT).build();
    }

    @Builder
    private record InvalidCase(String input, DcvError expectedDcvError) {
    }

}
