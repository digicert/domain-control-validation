package com.digicert.validation.utils;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.psl.DcvDomainName;
import com.ibm.icu.text.IDNA;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.IPAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
     * Whether to allow reserved/private IP addresses to bypass the reserved IP check.
     * <p>
     * Sourced from {@link com.digicert.validation.DcvConfiguration.DcvConfigurationBuilder#allowReservedIpAddresses(boolean)}.
     * Must only be {@code true} in non-production test environments.
     */
    private final boolean allowReservedIpAddresses;

    /**
     * Constructs a new DomainNameUtils with the specified DcvContext.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public DomainNameUtils(DcvContext dcvContext) {
        this.pslOverrideSupplier = dcvContext.get(PslOverrideSupplier.class);
        this.allowReservedIpAddresses = dcvContext.getDcvConfiguration().isAllowReservedIpAddresses();
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
        } catch (IllegalArgumentException e) {
            throw new InputException(DcvError.DOMAIN_INVALID_INCORRECT_NAME_PATTERN, e);
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

    // -----------------------------------------------------------------------
    // IP address helpers
    // -----------------------------------------------------------------------

    /**
     * Checks if the given value is an IP address (IPv4 or IPv6).
     * <p>
     * Uses BouncyCastle {@link IPAddress#isValid(String)} for consistent, pure-parser validation
     * with no DNS resolution side-effects.
     *
     * @param value the value to check
     * @return true if the value is a valid IPv4 or IPv6 address, false otherwise
     */
    public static boolean isIpAddress(String value) {
        if (StringUtils.isEmpty(value)) return false;
        return IPAddress.isValid(value);
    }

    /**
     * Validates the given value as either a domain name or an IP address.
     * <p>
     * If the value is a valid IP address (per {@link #isIpAddress(String)}), it is checked against
     * private and reserved ranges. Private IPv4 ranges (RFC 1918), reserved IPv4 ranges, loopback,
     * link-local, and multicast addresses are rejected with {@link DcvError#IP_ADDRESS_RESERVED}.
     * For IPv6, only Global Unicast addresses ({@code 2000::/3}) are permitted.
     * <p>
     * If the value does not look like an IP address, it is validated as a domain name via
     * {@link #validateDomainName(String)}.
     *
     * @param value the domain name or IP address to validate
     * @throws InputException if the value is empty, is a private/reserved IP address,
     *                        or is not a valid domain name
     */
    public void validateDomainOrIpAddress(String value) throws InputException {
        if (StringUtils.isEmpty(value)) {
            throw new InputException(DcvError.DOMAIN_REQUIRED);
        }
        if (isIpAddress(value)) {
            if (isPrivateOrReservedIpAddress(value)) {
                throw new InputException(DcvError.IP_ADDRESS_RESERVED);
            }
            return;
        }
        validateDomainName(value);
    }

    /**
     * Returns true if the IP address is in a private or reserved range.
     * <p>
     * For IPv4: rejects RFC 1918 private ranges, loopback, link-local, multicast, and other
     * IANA-reserved blocks (mirroring {@code ValidationUtils.isPrivateIpv4} and
     * {@code ValidationUtils.isReservedIpv4}).
     * <p>
     * For IPv6: rejects all addresses outside the Global Unicast range ({@code 2000::/3}).
     * <p>
     * If {@code allowReservedIpAddresses} is {@code true}, this method always returns {@code false}
     * and logs a warning instead of rejecting the address.
     *
     * @param ip a value already confirmed to be a valid IP address via {@link #isIpAddress(String)}
     * @return true if the address is private or reserved and the check is enforced, false otherwise
     */
    private boolean isPrivateOrReservedIpAddress(String ip) {
        boolean reserved = IPAddress.isValidIPv4(ip) ? isPrivateOrReservedIpv4(ip) : !isPublicIPv6(ip);
        if (reserved && allowReservedIpAddresses) {
            log.error("event_id={} ip_address={} message=\"Reserved IP check bypassed - ensure this is running in a test environment only\"",
                    LogEvents.RESERVED_IP_CHECK_BYPASSED, ip);
            return false;
        }
        return reserved;
    }

    /**
     * All IPv4 ranges that are private, reserved, or otherwise not permitted for DCV.
     * Initialised once as a static constant.
     * <p>
     * Covers:
     * <ul>
     *   <li>RFC 1918 private ranges: 10/8, 172.16/12, 192.168/16</li>
     *   <li>Loopback: 127/8 (RFC 5735)</li>
     *   <li>Multicast: 224/4 (RFC 1112)</li>
     *   <li>"This" network: 0/8 (RFC 1700)</li>
     *   <li>Shared address space: 100.64/10 (RFC 6598)</li>
     *   <li>Link-local: 169.254/16 (RFC 3927)</li>
     *   <li>IETF protocol assignments: 192.0.0/24 (RFC 5736)</li>
     *   <li>TEST-NET-1/2/3: 192.0.2/24, 198.51.100/24, 203.0.113/24 (RFC 5737)</li>
     *   <li>6to4 relay anycast: 192.88.99/24 (RFC 3068)</li>
     *   <li>Benchmarking: 198.18/15 (RFC 2544)</li>
     *   <li>Reserved: 240/4 – 255.255.255.255 (RFC 6890)</li>
     * </ul>
     */
    private static final Map<Long, Long> RESTRICTED_IPV4_RANGES = Map.ofEntries(
            Map.entry(ipToLong("10.0.0.0"),      ipToLong("10.255.255.255")),   // RFC 1918
            Map.entry(ipToLong("172.16.0.0"),    ipToLong("172.31.255.255")),   // RFC 1918
            Map.entry(ipToLong("192.168.0.0"),   ipToLong("192.168.255.255")),  // RFC 1918
            Map.entry(ipToLong("127.0.0.0"),     ipToLong("127.255.255.255")),  // loopback RFC 5735
            Map.entry(ipToLong("224.0.0.0"),     ipToLong("239.255.255.255")),  // multicast RFC 1112
            Map.entry(ipToLong("0.0.0.0"),       ipToLong("0.255.255.255")),    // RFC 1700
            Map.entry(ipToLong("100.64.0.0"),    ipToLong("100.127.255.255")),  // RFC 6598
            Map.entry(ipToLong("169.254.0.0"),   ipToLong("169.254.255.255")),  // RFC 3927 link-local
            Map.entry(ipToLong("192.0.0.0"),     ipToLong("192.0.0.255")),      // RFC 5736
            Map.entry(ipToLong("192.0.2.0"),     ipToLong("192.0.2.255")),      // RFC 5737
            Map.entry(ipToLong("192.88.99.0"),   ipToLong("192.88.99.255")),    // RFC 3068
            Map.entry(ipToLong("198.18.0.0"),    ipToLong("198.19.255.255")),   // RFC 2544
            Map.entry(ipToLong("198.51.100.0"),  ipToLong("198.51.100.255")),   // RFC 5737
            Map.entry(ipToLong("203.0.113.0"),   ipToLong("203.0.113.255")),    // RFC 5737
            Map.entry(ipToLong("240.0.0.0"),     ipToLong("255.255.255.255"))   // RFC 6890
    );

    /**
     * Returns true if the IPv4 address is in a private or reserved range.
     * Covers RFC 1918 private ranges, loopback (127.x), link-local (169.254.x),
     * multicast (224-239.x), and additional IANA-reserved blocks.
     */
    private static boolean isPrivateOrReservedIpv4(String ip) {
        long addr = ipToLong(ip);
        for (Map.Entry<Long, Long> entry : RESTRICTED_IPV4_RANGES.entrySet()) {
            if (isIpInRange(addr, entry.getKey(), entry.getValue())) return true;
        }
        return false;
    }

    /**
     * Returns true if the IPv6 address is publicly routable (Global Unicast, {@code 2000::/3})
     * and is not an IANA special-purpose block reserved within that range.
     * <p>
     * Passes the Global Unicast guard ({@code 2000::/3}, first 3 bits {@code 001}) and then
     * rejects the following IANA-reserved sub-ranges (mirroring the IPv4 TEST-NET / reserved
     * block treatment):
     * <ul>
     *   <li>{@code 2001:db8::/32} — documentation prefix (RFC 3849)</li>
     *   <li>{@code 2001::/23} — IETF Protocol Assignments, covering Teredo ({@code 2001::/32}),
     *       benchmarking ({@code 2001:2::/48}), ORCHID ({@code 2001:10::/28}),
     *       and ORCHID v2 ({@code 2001:20::/28})</li>
     * </ul>
     * All other ranges (loopback {@code ::1}, link-local {@code fe80::/10},
     * ULA {@code fc00::/7}, etc.) are also rejected because they fall outside {@code 2000::/3}.
     */
    private static boolean isPublicIPv6(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] bytes = addr.getAddress();
            if (bytes.length != 16) return false; // not IPv6
            // Must be in Global Unicast range 2000::/3 (first 3 bits = 001)
            if ((bytes[0] & 0xE0) != 0x20) return false;
            // Reject 2001:db8::/32 — documentation prefix (RFC 3849), not a real routable address.
            // Equivalent to IPv4 TEST-NET-1/2/3 rejection.
            if (bytes[0] == 0x20 && bytes[1] == 0x01
                    && bytes[2] == 0x0d && bytes[3] == (byte) 0xb8) return false;
            // Reject 2001::/23 — IETF Protocol Assignments (covers Teredo 2001::/32,
            // benchmarking 2001:2::/48, ORCHID 2001:10::/28, ORCHID v2 2001:20::/28).
            // The /23 mask means bytes[0]==0x20, bytes[1]==0x01, top-7 bits of bytes[2]==0x00.
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] & 0xFE) == 0x00) return false;
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /** Converts a dotted-decimal IPv4 string to a long value for range comparisons. */
    private static long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        return (Long.parseLong(parts[0]) << 24) +
               (Long.parseLong(parts[1]) << 16) +
               (Long.parseLong(parts[2]) << 8) +
                Long.parseLong(parts[3]);
    }

    /** Returns true if {@code address} falls within [{@code begin}, {@code end}] inclusive. */
    private static boolean isIpInRange(long address, long begin, long end) {
        return address >= begin && address <= end;
    }
}