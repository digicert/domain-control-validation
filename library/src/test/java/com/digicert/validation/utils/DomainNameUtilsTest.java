package com.digicert.validation.utils;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.exceptions.InputException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DomainNameUtilsTest {

    private static DomainNameUtils domainNameUtils;
    private static PslOverrideSupplier supplierWithOverrides;

    public record OverrideData(String domain, String tld) { }

    @BeforeAll
    static void beforeAll() {
        NoopPslOverrideSupplier pslOverrideSupplier = new NoopPslOverrideSupplier();
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .pslOverrideSupplier(pslOverrideSupplier)
                .build();
        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        domainNameUtils = new DomainNameUtils(dcvContext);

        // domain, what to use as tld
        List<OverrideData> overrideData = List.of(
                new OverrideData("blogspot.com", "com"), // Allow blogspot.com to be a valid domain
                new OverrideData("foo.example.com", "foo.example.com"), // Treat foo.example.com as a TLD
                new OverrideData("invalid", "invalid"), // Treat "invalid" as a legit TLD
                new OverrideData("google", null)); // Treat ".google" as an invalid TLD
        supplierWithOverrides = domain -> {
            Optional<OverrideData> overrideOpt = overrideData.stream()
                    .filter(override -> domain.endsWith(override.domain()))
                    .findFirst();
            if (overrideOpt.isPresent() && overrideOpt.get().tld() == null) {
                throw new InputException(DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX);
            }
            return overrideOpt.map(OverrideData::tld);
        };
    }

    static Stream<Arguments> validateDomainNameTestData_goodDomains() {
        return Stream.of(
                Arguments.of("example.com"),
                Arguments.of("a.b.c.d.e.co.uk"),
                Arguments.of("xn--tda.example.com")
        );
    }
    @ParameterizedTest
    @MethodSource("validateDomainNameTestData_goodDomains")
    void validateDomainName_goodDomain(String domain) throws InputException {
        domainNameUtils.validateDomainName(domain);
    }

    static Stream<Arguments> validateDomainNameTestData_badDomains() {
        return Stream.of(
                Arguments.of("a".repeat(64) + ".example.com", DcvError.DOMAIN_INVALID_INCORRECT_NAME_PATTERN), // label too long
                Arguments.of("aaa.".repeat(64) + "example.com", DcvError.DOMAIN_INVALID_TOO_LONG), // domain too long
                Arguments.of("foo.bd", DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX), // *.bd is in the PSL
                Arguments.of("blogspot.com", DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX), // private TLD
                Arguments.of("example.invalid", DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX), // invalid TLD
                Arguments.of("invalid", DcvError.DOMAIN_INVALID_INCORRECT_NAME_PATTERN) // invalid TLD
        );
    }

    @ParameterizedTest
    @MethodSource("validateDomainNameTestData_badDomains")
    void validateDomainName_badDomain(String domain, DcvError expectedError) {
        try {
            domainNameUtils.validateDomainName(domain);
            fail();
        } catch (InputException e) {
            assertEquals(1, e.getErrors().size());
            assertTrue(e.getErrors().contains(expectedError), "expected error: " + expectedError + ", got: " + e.getErrors());
        }
    }


    static Stream<Arguments> provideDomainRegexTestData() {
        return Stream.of(
                Arguments.of("example.com", true),
                Arguments.of("sub.example.com", true),
                Arguments.of("sub.sub.sub.example.com", true),
                Arguments.of("h-y-p-h-e-n-s.ex-ample.com", true),
                Arguments.of("invalid.", false),
                Arguments.of("chars?.invalid.com", false),
                Arguments.of("-hyphens.invalid.com", false),
                Arguments.of("hyphens-.invalid.com", false)
        );
    }

    @ParameterizedTest
    @MethodSource("provideDomainRegexTestData")
    void domainMatchesRegex(String domain, boolean expected) {
        assertEquals(expected, DomainNameUtils.domainMatchesRegex(domain));
    }

    static Stream<Arguments> provideWildcardDomainTestData() {
        return Stream.of(
                Arguments.of("example.com", "example.com"),
                Arguments.of("*.example.com", "example.com"),
                Arguments.of("sub.example.com", "sub.example.com"),
                Arguments.of("*.sub.example.com", "sub.example.com")
        );
    }

    @ParameterizedTest
    @MethodSource("provideWildcardDomainTestData")
    void removeWildCard(String domain, String expected) {
        assertEquals(expected, DomainNameUtils.removeWildCard(domain));
    }

    static Stream<Arguments> provideLDHLabelTestData() {
        return Stream.of(
                Arguments.of("example.com", false),
                Arguments.of("a.b.c.d.example.com", false),
                Arguments.of("xn--tda.example.com", false),
                Arguments.of("a.xn--tda.com", false),
                Arguments.of("a.example.xn--tda", false),
                Arguments.of("ex--example.example.com", true),
                Arguments.of("a.ex--example.com", true),
                Arguments.of("a.example.ex--example", true),
                Arguments.of("xn--abcd.example.com", true),
                Arguments.of("a.example.xn--abcd", true)
        );
    }

    @ParameterizedTest
    @MethodSource("provideLDHLabelTestData")
    void domainContainsInvalidReservedLDHLabel(String domain, boolean expected) {
        assertEquals(expected, DomainNameUtils.domainContainsInvalidReservedLDHLabel(domain));
    }

    static Stream<Arguments> provideGetDomainAndParentsTestData() {
        return Stream.of(
                Arguments.of("foo.blogspot.com", List.of("foo.blogspot.com")),
                Arguments.of("sub.example.com", List.of("sub.example.com", "example.com")),
                Arguments.of("a.b.c.d.e.co.uk", List.of("a.b.c.d.e.co.uk", "b.c.d.e.co.uk", "c.d.e.co.uk", "d.e.co.uk", "e.co.uk"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideGetDomainAndParentsTestData")
    void getDomainAndParents_happyDay(String domain, List<String> expected) throws InputException {
        List<String> actual = domainNameUtils.getDomainAndParents(domain);
        assertEquals(expected, actual);
    }

    static Stream<Arguments> provideGetDomainAndParentsInvalidTestData() {
        return Stream.of(
                Arguments.of("sub.example.invalid"),
                Arguments.of("sub.example.other.invalid"),
                Arguments.of("example.invalid"),
                // This is an invalid domain because it is in the PSL
                Arguments.of("schools.nsw.edu.au")
        );
    }

    @ParameterizedTest
    @MethodSource("provideGetDomainAndParentsInvalidTestData")
    void getDomainAndParents_invalidDomains(String domain) {
        assertThrows(InputException.class, () -> domainNameUtils.getDomainAndParents(domain));
    }

    static Stream<Arguments> provideGetBaseDomainTestData() {
        return Stream.of(
                Arguments.of("foo.blogspot.com", "foo.blogspot.com"),
                Arguments.of("example.com", "example.com"),
                Arguments.of("www.google.co.uk", "google.co.uk"),
                Arguments.of("a.b.c.d.e.example.com", "example.com")
        );
    }

    @ParameterizedTest
    @MethodSource("provideGetBaseDomainTestData")
    void getBaseDomain_happyDay(String domain, String expected) throws InputException {
        assertEquals(expected, domainNameUtils.getBaseDomain(domain));
    }

    static Stream<Arguments> provideGetBaseDomainInvalidTestData() {
        return Stream.of(
                Arguments.of("blogspot.com"),
                Arguments.of("example.invalid")
        );
    }

    @ParameterizedTest
    @MethodSource("provideGetBaseDomainInvalidTestData")
    void getBaseDomain_invalidDomain(String domain) {
        assertThrows(InputException.class, () -> domainNameUtils.getBaseDomain(domain));
    }

    static Stream<Arguments> providePslOverridesTestData() {
        /*
            From above, the test PSL overrides are:
            List<OverrideData> overrideData = List.of(
                    new OverrideData("blogspot.com", "com"), // Allow blogspot.com to be a valid domain
                    new OverrideData("foo.example.com", "foo.example.com"), // Treat foo.example.com as a TLD
                    new OverrideData("invalid", "invalid"), // Treat "invalid" as a legit TLD
                    new OverrideData("google", null)); // Treat ".google" as an invalid TLD
         */
        // domain, expected base domain
        return Stream.of(
                Arguments.of("blogspot.com", "blogspot.com"),
                Arguments.of("foo.blogspot.com", "blogspot.com"),
                Arguments.of("test.foo.example.com", "test.foo.example.com"),
                Arguments.of("bar.example.com", "example.com"),
                Arguments.of("example.com", "example.com"),
                Arguments.of("valid.invalid", "valid.invalid"),
                Arguments.of("test.valid.invalid", "valid.invalid")
        );
    }

    @ParameterizedTest
    @MethodSource("providePslOverridesTestData")
    void getBaseDomainWithPslOverrides(String domain, String expectedBaseDomain) throws InputException {
        DcvContext dcvContext = mock(DcvContext.class);
        doReturn(supplierWithOverrides).when(dcvContext).get(PslOverrideSupplier.class);
        DomainNameUtils overriddenUtils = new DomainNameUtils(dcvContext);
        assertEquals(expectedBaseDomain, overriddenUtils.getBaseDomain(domain));
    }

    static Stream<Arguments> providePslOverridesInvalidTestData() {
        /*
            From above, the test PSL overrides are:
            List<OverrideData> overrideData = List.of(
                    new OverrideData("blogspot.com", "com"), // Allow blogspot.com to be a valid domain
                    new OverrideData("foo.example.com", "foo.example.com"), // Treat foo.example.com as a TLD
                    new OverrideData("invalid", "invalid"), // Treat "invalid" as a legit TLD
                    new OverrideData("google", null)); // Treat ".google" as an invalid TLD
         */
        // domain, expected base domain
        return Stream.of(
                Arguments.of("foo.example.com"),
                Arguments.of("invalid"),
                Arguments.of("example.google")
        );
    }

    @ParameterizedTest
    @MethodSource("providePslOverridesInvalidTestData")
    void getBaseDomainWithPslOverrides_invalid(String domain) {
        DcvContext dcvContext = mock(DcvContext.class);
        doReturn(supplierWithOverrides).when(dcvContext).get(PslOverrideSupplier.class);
        DomainNameUtils overriddenUtils = new DomainNameUtils(dcvContext);
        assertThrows(InputException.class, () -> overriddenUtils.getBaseDomain(domain));
    }

    static Stream<Arguments> provideEmailAddressTestData() {
        return Stream.of(
                Arguments.of("a@example.com", true),
                Arguments.of("person@example.com", true),
                Arguments.of("a.real.person@example.com", true),
                Arguments.of("mailhost!user-name@example.com", true),
                Arguments.of("invalid.com", false),
                Arguments.of("person..example@invalid.com", false),
                Arguments.of("person@example.com@invalid.com", false),
                Arguments.of("spe(cial)@example.com", false),
                Arguments.of("spe<cial>@example.com", false),
                Arguments.of("spe[cial]@example.com", false),
                Arguments.of("spe:cial@example.com", false),
                Arguments.of("spe;cial@example.com", false),
                Arguments.of("spe@cial@example.com", false),
                Arguments.of("spe,cial@example.com", false),
                Arguments.of("spe\\cial@example.com", false),
                Arguments.of("spe/cial@example.com", true),
                Arguments.of("spe!cial@example.com", true),
                Arguments.of("spe#cial@example.com", true),
                Arguments.of("spe$cial@example.com", true),
                Arguments.of("spe%cial@example.com", true),
                Arguments.of("spe^cial@example.com", true),
                Arguments.of("spe&cial@example.com", true),
                Arguments.of("spe*cial@example.com", true),
                Arguments.of("spe+cial@exmaple.com", true),
                Arguments.of("spe`cial@example.com", true),
                Arguments.of("spe|cial@example.com", true),
                Arguments.of("spe{cial}@example.com", true),
                Arguments.of("spe_cial@example.com", true),
                Arguments.of("spe-cial@example.com", true),
                Arguments.of("spe~cial@example.com", true),
                Arguments.of("spe=cial@example.com", true),
                Arguments.of("spe'cial@example.com", true)
        );
    }

    @ParameterizedTest
    @MethodSource("provideEmailAddressTestData")
    void isValidEmailAddress(String email, boolean isValid) {
        assertEquals(isValid, DomainNameUtils.isValidEmailAddress(email));
    }

    private Stream<Arguments> emailProvider() {
        return Stream.of(
                Arguments.of("dnstxt@email.com", true),
                Arguments.of("dns.txt1@email.com", true),
                Arguments.of("dnstxt@email.com,", false),
                Arguments.of(" dnstxt@email.com", false),
                Arguments.of("dnstxt@email.com  ", false),
                Arguments.of("dnstxt@email.com@", false),
                Arguments.of("d@e.", false),
                Arguments.of("d@e", false),
                Arguments.of("@email.com", false),
                Arguments.of("dnstxt@-email.com", false),
                Arguments.of(" ", false),
                Arguments.of("", false)
        );
    }

    @DisplayName("Test validateEmailAddress with various inputs")
    @ParameterizedTest(name = "{index} => email={0}, isValid={1}")
    @MethodSource("emailProvider")
    void testValidateEmailAddress(String email, boolean isValid) {
        if (isValid) {
            assertTrue(DomainNameUtils.isValidEmailAddress(email));
        } else {
            assertFalse(DomainNameUtils.isValidEmailAddress(email));
        }
    }
}