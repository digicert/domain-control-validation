package com.digicert.validation.utils;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.psl.DcvDomainName;
import com.ibm.icu.text.IDNA;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.ibm.icu.text.IDNA.NONTRANSITIONAL_TO_ASCII;
import static com.ibm.icu.text.IDNA.NONTRANSITIONAL_TO_UNICODE;

/**
 * Utility class for domain name validation and manipulation.
 * <p>
 * This class provides various utility methods for validating and manipulating domain names.
 * It includes methods for checking the validity of domain names and labels, removing wildcard prefixes,
 * and determining the base domain and parent domains. The class also handles special cases such as
 * reserved LDH labels and IDNA (Internationalized Domain Names in Applications) processing.
 */
@Slf4j
public class DomainNameUtils {

    /** Domain name labels consist of up to 63 letters, numbers, and hyphens, but cannot start or end with a hyphen. */
    private static final String DOMAIN_LABEL_REGEX = "([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)";

    /** Pattern for a domain label. */
    private static final Pattern DOMAIN_LABEL_PATTERN = Pattern.compile("^" + DOMAIN_LABEL_REGEX + "$");

    /** Regex pattern for domains. Domains are two or more "."-separated labels. */
    private static final String DOMAIN_REGEX = "("+DOMAIN_LABEL_REGEX+"\\.)+" + DOMAIN_LABEL_REGEX;

    /** Compiled pattern for a domain. */
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^" + DOMAIN_REGEX + "$");

    /**
     * Per <a href="https://datatracker.ietf.org/doc/rfc5890/">https://datatracker.ietf.org/doc/rfc5890/</a>, labels that start with "??--" are "tagged domain names".
     * Currently, the only allowed start for such labels is "xn--".
     * This is a regex pattern for the "xn--" label.
     */
    public static final String XN_LABEL = "xn";

    /** Separator for reserved LDH labels. */
    public static final String R_LDH_LABEL_SEPARATOR = "--";

    /** Maximum length of a domain name. */
    private static final int MAX_DOMAIN_LENGTH = 256;

    /** Regex for one or more of the allowed char set for the local-part of a valid email address. */
    private static final String EMAIL_CHAR_REGEX = "[a-zA-Z0-9_!#$%&'*+/=?`{|}~^-]+";

    /**
     *  Regex for the local-part of an email address
     *  <p>
     *  The local-part of an email address can contain '.'s, but they cannot be the first or last character, and they
     *  cannot appear consecutively.
     */
    private static final String EMAIL_LOCAL_PART_REGEX = EMAIL_CHAR_REGEX + "(\\." + EMAIL_CHAR_REGEX + ")*";

    /**
     * Compiled pattern for validating email addresses.
     * <p>
     * Email address consist of a local-part and a domain, with an @ separating them.
     */
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^" + EMAIL_LOCAL_PART_REGEX + "@" + DOMAIN_REGEX + "$");

    /**
     * IDNA instance for UTS 46.
     * <p>
     * This instance of the IDNA class is configured for UTS 46 (Unicode Technical Standard #46) processing.
     * It is used to handle internationalized domain names, converting them between Unicode and ASCII
     * representations.
     */
    private static final IDNA UTS_46_INSTANCE = IDNA.getUTS46Instance(NONTRANSITIONAL_TO_ASCII | NONTRANSITIONAL_TO_UNICODE);

    /**
     * Supplier for Public Suffix List overrides.
     * <p>
     * This supplier provides overrides for the Public Suffix List (PSL). It is used to handle special cases
     * where the default PSL does not apply, allowing for custom domain suffix rules.
     */
    private final PslOverrideSupplier pslOverrideSupplier;

    /**
     * Constructs a new DomainNameUtils with the specified DcvContext.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public DomainNameUtils(DcvContext dcvContext) {
        this.pslOverrideSupplier = dcvContext.get(PslOverrideSupplier.class);
    }

    /**
     * Validates the given domain name.
     * <p>
     * This method validates the provided domain name by checking its length, format, and reserved LDH labels.
     * It also ensures that the domain name is under a valid public suffix.
     *
     * @param domainName the domain name to validate
     * @throws InputException if the domain name is invalid
     */
    public void validateDomainName(String domainName) throws InputException {
        if (StringUtils.isEmpty(domainName)) {
            throw new InputException(DcvError.DOMAIN_REQUIRED);
        }

        if (domainName.length() > MAX_DOMAIN_LENGTH) {
            log.info("event_id={} domain={} length={}", LogEvents.INVALID_DOMAIN_LENGTH, truncateDomainName(domainName), domainName.length());
            throw new InputException(DcvError.DOMAIN_INVALID_TOO_LONG);
        }

        String nonWildCardDomain = removeWildCard(domainName);

        if (!domainMatchesRegex(nonWildCardDomain)) {
            log.info("event_id={} domain={}", LogEvents.INVALID_DOMAIN_NAME, domainName);
            throw new InputException(DcvError.DOMAIN_INVALID_INCORRECT_NAME_PATTERN);
        }

        if (domainContainsInvalidReservedLDHLabel(nonWildCardDomain)) {
            log.info("event_id={} domain={}", LogEvents.INVALID_RESERVED_LDH_LABEL, domainName);
            throw new InputException(DcvError.DOMAIN_INVALID_BAD_LDH_LABEL);
        }

        // This method will throw an exception if the domainName is invalid
        getBaseDomain(nonWildCardDomain);
    }

    /**
     * Utility function to prevent logging a domain name that is excessively long.
     *
     * @param domainName the domain name to truncate
     * @return up to MAX_DOMAIN_LENGTH+10 chars of the domain name followed by "..." if the domain name was truncated
     */
    private String truncateDomainName(String domainName) {
        return domainName.length() > MAX_DOMAIN_LENGTH + 10 ? domainName.substring(0, MAX_DOMAIN_LENGTH + 10) + "..." : domainName;
    }

    /**
     * Checks if the given domain label is matches the DOMAIN_LABEL_PATTERN.
     *
     * @param domainLabel the domain label to check
     * @return true if the domain label is valid, false otherwise
     */
    public static boolean isValidDomainLabel(String domainLabel) {
        return DOMAIN_LABEL_PATTERN.matcher(domainLabel).matches();
    }

    /**
     * Checks if the given domain matches the domain regex pattern.
     *
     * @param domain the domain to check
     * @return true if the domain matches the regex pattern, false otherwise
     */
    public static boolean domainMatchesRegex(String domain) {
        return DOMAIN_PATTERN.matcher(domain).matches();
    }

    /**
     * Removes the wildcard prefix from the given domain name and ensures it is lowercase.
     *
     * @param domainName the domain name to process
     * @return the domain name without the wildcard prefix
     */
    static String removeWildCard(String domainName) {
        return StringUtils.removeStart(domainName, "*.").toLowerCase();
    }

    /**
     * Determines if the domain contains invalid reserved LDH labels, including verifying any punycode present is valid.
     *
     * @param domain the domain to check
     * @return true if the domain contains invalid reserved LDH labels, false otherwise
     */
    static boolean domainContainsInvalidReservedLDHLabel(String domain) {
        for (String label : domain.split("\\.")) {
            if (label.startsWith(R_LDH_LABEL_SEPARATOR, 2)) {
                if (!label.startsWith(XN_LABEL)) {
                    return true;
                }
            } else {
                continue;
            }

            IDNA.Info idnaInfo = new IDNA.Info();
            UTS_46_INSTANCE.nameToUnicode(label, new StringBuilder(), idnaInfo);

            // If there are errors, it is invalid.
            if (idnaInfo.hasErrors()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the domain and its parent domains.
     * <p>
     * This method returns a list of the provided domain name and all parent domains up to the base domain. For example,
     * "a.b.c.d.e.com" would return the list ["a.b.c.d.e.com", "b.c.d.e.com", "c.d.e.com", "d.e.com", "e.com"]
     *
     * @param domain the domain to process
     * @return a list of the domain and its parent domains
     * @throws InputException if the domain is invalid
     */
    public List<String> getDomainAndParents(String domain) throws InputException {
        String lowerCaseDomain = domain.toLowerCase();
        int baseDomainLength = getBaseDomain(lowerCaseDomain).length();

        List<String> domains = new ArrayList<>();
        // Add the original domain
        domains.add(lowerCaseDomain);

        // Now add any parent domains (but not the TLD)
        while (lowerCaseDomain.length() > baseDomainLength && lowerCaseDomain.contains(".")) {
            lowerCaseDomain = lowerCaseDomain.substring(lowerCaseDomain.indexOf('.') + 1);
            domains.add(lowerCaseDomain);
        }

        return domains;
    }

    /**
     * Gets the base domain of the given domain name.
     * <p>
     * This method returns the base domain of the provided domain name. It uses the Public Suffix List (PSL)
     * and any overrides to determine the base domain.
     *
     * @param domainName the domain name to process
     * @return the base domain
     * @throws InputException if the domain is invalid
     */
    public String getBaseDomain(String domainName) throws InputException {
        Optional<String> pslOverride = pslOverrideSupplier.getPublicSuffixOverride(domainName);
        if (pslOverride.isPresent()) {
            if (domainName.equalsIgnoreCase(pslOverride.get())) {
                // If the domain is the same as the override, we are treating it as a TLD rather than a valid domain
                throw new InputException(DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX);
            }

            /*
              This code determines the base domain of a given domainName using a PSL Override.
              It finds the position of the last dot ('.') in the domainName that is NOT part of the pslOverride.

              Example:
              domainName: "foo.bar.sub.example.co.uk", pslOverride: "example.co.uk"
              - domainName.length() = 24
              - pslOverride.length() = 13
              - domainName.length() - pslOverride.length() - 2 = 24 - 13 - 2 = 9
              - domainName.lastIndexOf('.', 9) = 7 (the dot after "foo.bar")
              - baseDomainStart = 7
              - domainName.substring(baseDomainStart + 1) = "sub.example.co.uk"

                If there are no other labels, then the base domain is the domainName itself.
              */
            int baseDomainStart = domainName.lastIndexOf('.', domainName.length() - pslOverride.get().length() - 2);
            if (baseDomainStart == -1) {
                return domainName;
            } else {
                return domainName.substring(baseDomainStart + 1);
            }
        }
        try {
            DcvDomainName dcvDomainName = DcvDomainName.from(domainName);
            if (dcvDomainName.hasRegistrySuffix()) {
                return dcvDomainName.topDomainUnderRegistrySuffix().toString();
            }
            else {
                throw new InputException(DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX);
            }
        } catch (IllegalStateException e) {
            throw new InputException(DcvError.DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX, e);
        }
    }

    /**
     * Checks if the given email address is valid.
     * <p>
     * This method checks if the provided email address matches the EMAIL_PATTERN.
     * </p>
     *
     * @param email the email address to check
     * @return true if the email address is valid, false otherwise
     */
    public static boolean isValidEmailAddress(String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }
}