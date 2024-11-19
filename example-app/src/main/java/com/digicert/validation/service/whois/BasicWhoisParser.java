package com.digicert.validation.service.whois;

import lombok.Getter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * BasicWhoisParser is a class that implements the WhoisParser interface.
 * It parses raw WHOIS data to extract email addresses and contact information.
 * <p>
 * This class is designed to handle the parsing of raw WHOIS data, which is often unstructured and varies between different
 * domain registrars. While this implementation provides a basic parsing mechanism, users of this library are encouraged
 * to provide their own implementation of `WhoisParser` if they have specific needs.
 */
public class BasicWhoisParser implements WhoisParser {

    /**
     * The constructor initializes a new instance of the BasicWhoisParser class.
     */
    public BasicWhoisParser() {
        // Default constructor
    }

    /**
     * Parses the raw WHOIS data to extract email addresses and contact information.
     * <p>
     * This method takes a string containing raw WHOIS data and processes it to extract relevant contact information. The
     * extracted data includes email addresses, organization names, and phone numbers, which are then encapsulated in a
     * ParsedWhoisData object.
     *
     * @param rawWhoisData the raw WHOIS data as a string
     * @return ParsedWhoisData containing the extracted email addresses and contact information
     */
    public ParsedWhoisData parseWhoisRecord(String rawWhoisData) {
        List<String> whoisLines = Arrays.stream(rawWhoisData.split("\n")).toList();
        HashSet<String> emails = new HashSet<>();

        ParsedWhoisContactData registrantContact = new ParsedWhoisContactData(WhoisLabels.REGISTRANT_CONTACT_LABEL);
        ParsedWhoisContactData techContact = new ParsedWhoisContactData(WhoisLabels.TECH_CONTACT_LABEL);
        ParsedWhoisContactData techContact2 = new ParsedWhoisContactData(WhoisLabels.TECH_CONTACT_LABEL);
        ParsedWhoisContactData adminContact = new ParsedWhoisContactData(WhoisLabels.ADMIN_CONTACT_LABEL);
        ParsedWhoisContactData recordContact = new ParsedWhoisContactData(WhoisLabels.RECORD_CONTACT_LABEL);

        int colonIndex;
        int atIndex;

        for (String line : whoisLines) {
            String trimmed = line.trim();
            atIndex = trimmed.indexOf("@");
            colonIndex = trimmed.indexOf(":");

            if (colonIndex > 0) {
                // Label should be a trimmed version of the line, up to the colon.
                // Since some TLDs return dots instead of spaces between the label and colon, we'll replace those with spaces
                // Replace e-mail with email and all remaining dashes and underscores with spaces to simplify the comparison
                // line "Admin_Contact_E-mail" should match "admin contact email"

                String label = trimmed.substring(0, colonIndex).toLowerCase().replace(".", " ").trim();
                if (colonIndex < atIndex && WhoisLabels.WHOIS_DOMAIN_EMAIL_PREFIXES.contains(label)) {
                    String foundEmail = trimmed.substring(colonIndex + 1).trim();

                    if (label.startsWith("registrant") || label.endsWith("registrant")) {
                        registrantContact.setEmail(foundEmail);
                    }
                    else if (label.startsWith("tec") || label.endsWith("tech") || label.endsWith("tech1")) {
                        techContact.setEmail(foundEmail);
                    }
                    else if (label.endsWith("tech2")) {
                        techContact2.setEmail(foundEmail);
                    }
                    else if (label.startsWith("adm") || label.startsWith("ac") || label.endsWith("admin")) {
                        adminContact.setEmail(foundEmail);
                    }

                    emails.add(foundEmail);
                } else if (WhoisLabels.WHOIS_DOMAIN_ORG_NAME_PREFIXES.contains(label)) {
                    String foundOrgName = trimmed.substring(colonIndex + 1).trim();

                    if (label.startsWith("registrant")) {
                        registrantContact.setOrgName(foundOrgName);
                    }
                    else if (label.startsWith("tech")) {
                        techContact.setOrgName(foundOrgName);
                    }
                    else if (label.startsWith("admin")) {
                        adminContact.setOrgName(foundOrgName);
                    }
                    else if (label.startsWith("org")) {
                        recordContact.setOrgName(foundOrgName);
                    }
                }
                else if (WhoisLabels.WHOIS_DOMAIN_PHONE_PREFIXES.contains(label)) {
                    String foundPhone = trimmed.substring(colonIndex + 1).trim();

                    if (label.startsWith("registrant") || label.endsWith("registrant")) {
                        registrantContact.setPhone(foundPhone);
                    }
                    else if (label.startsWith("tec") || label.endsWith("tech") || label.endsWith("tech1")) {
                        techContact.setPhone(foundPhone);
                    }
                    else if (label.endsWith("tech2")) {
                        techContact2.setPhone(foundPhone);
                    }
                    else if (label.startsWith("adm") || label.startsWith("ac") || label.endsWith("admin")) {
                        adminContact.setPhone(foundPhone);
                    }
                }
            }
        }

        List<ParsedWhoisContactData> domainContacts = List.of(adminContact, techContact, techContact2, registrantContact, recordContact);
        return new ParsedWhoisData(rawWhoisData, emails, domainContacts);
    }

    /**
     * Returns a string representing the name of the parser.
     *
     * @return the name of the parser
     */
    public String getName() {
        return WhoisLabels.NAME;
    }

    /**
     * Returns the set of parsable email labels.
     * <p>
     * This method returns a set of strings representing the email labels that the parser can recognize and process. These
     * labels are used to identify email addresses in the raw WHOIS data.
     *
     *
     * @return the set of parsable email labels
     */
    public Set<String> getParsableEmailLabels() {
        return WhoisLabels.WHOIS_DOMAIN_EMAIL_PREFIXES;
    }

    /**
     * WhoisLabels is a static class that contains constants for WHOIS labels.
     * <p>
     * The WhoisLabels class defines a set of constants used by the BasicWhoisParser to identify and normalize contact
     * information in WHOIS data. These constants include labels for email addresses, organization names, and phone numbers,
     * as well as a parser name.
     *
     */
    @Getter
    public static class WhoisLabels {

        /**
         * Default constructor for the WhoisLabels class.
         */
        private WhoisLabels() {
            // Default constructor
        }

        /**
         * The name of the parser.
         * <p>
         * This constant is used to identify the specific implementation of the WhoisParser interface
         * provided by the BasicWhoisParser class. The name can be useful for logging, debugging,
         * or selecting the appropriate parser in applications that support multiple parsers.
         */
        private static final String NAME = "basic";

        /**
         * The label for the administrative contact.
         * <p>
         * This constant defines the label used to identify the administrative contact in WHOIS data.
         */
        private static final String ADMIN_CONTACT_LABEL = "administrative";

        /**
         * The label for the technical contact.
         * <p>
         * This constant defines the label used to identify the technical contact in WHOIS data.\
         */
        private static final String TECH_CONTACT_LABEL = "technical";

        /**
         * The label for the registrant contact.
         * <p>
         * This constant defines the label used to identify the registrant contact in WHOIS data.
         */
        private static final String REGISTRANT_CONTACT_LABEL = "registrant";

        /**
         * The label for the record contact.
         * <p>
         * This constant defines the label used to identify the record contact in WHOIS data.
         */
        private static final String RECORD_CONTACT_LABEL = "record";

        /**
         * Set holding all prefixes used to identify email addresses among entries in whois data.
         * <p>
         * This set of constants defines the prefixes used to identify email addresses in WHOIS data.
         */
        private static final Set<String> WHOIS_DOMAIN_EMAIL_PREFIXES = new HashSet<>();

        /**
         * Prefixes used to identify organization names among entries in whois data.
         * <p>
         * This set of constants defines the prefixes used to identify organization names in WHOIS data.
         */
        private static final Set<String> WHOIS_DOMAIN_ORG_NAME_PREFIXES = new HashSet<>();

        /**
         * Prefixes used to identify phone numbers among entries in whois data.
         * <p>
         * This set of constants defines the prefixes used to identify phone numbers in WHOIS data.
         */
        private static final Set<String> WHOIS_DOMAIN_PHONE_PREFIXES = new HashSet<>();

        /**
         * Prefixes used to identify email addresses among entries in whois data.
         * <p>
         * This set of constants defines the normalized prefixes used to identify email addresses in WHOIS data.
         */
        private static final Set<String> normalizedEmailLabels = Set.of(
                // registrant variants
                "registrant email",
                "registrant contact email",
                "courriel registrant",

                // tech contact variants
                "tec email",
                "tech email",
                "technical email",
                "technical contact email",
                "courriel contact tech1",
                "courriel contact tech2",

                // admin contact variants
                "ac email",
                "adm email",
                "admin email",
                "admin contact email",
                "administrative email",
                "administrative contact email",
                "courriel contact admin"
        );

        /**
         * Prefixes used to identify organization names we are interested in among entries in whois data.
         * <p>
         * This set of constants defines the normalized prefixes used to identify organization names in WHOIS data.
         *
         */
        private static final Set<String> normalizedOrgNameLabels = Set.of(
                "registrant organization",
                "admin organization",
                "tech organization",
                "org name"
        );

        /**
         * Prefixes used to identify phone numbers we are interested in among entries in whois data.
         * <p>
         * This set of constants defines the normalized prefixes used to identify phone numbers in WHOIS data.
         *
         */
        private static final Set<String> normalizedPhoneLabels = Set.of(
                "registrant phone",
                "telephone registrant",
                "admin phone",
                "telephone contact admin",
                "tech phone",
                "telephone contact tech1",
                "telephone contact tech2"
        );

        static {
            // The normalized list simplifies what we want to store. Build the full list to pass to cloud whois
            for (String normalizedLabel : normalizedEmailLabels) {
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel);
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel.replace("email", "e-mail"));
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel.replace(" ", "-"));
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel.replace(" ", "-").replace("email", "e-mail"));
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel.replace(" ", "_"));
                WHOIS_DOMAIN_EMAIL_PREFIXES.add(normalizedLabel.replace(" ", "_").replace("email", "e-mail"));
            }

            for (String normalizedLabel : normalizedOrgNameLabels) {
                WHOIS_DOMAIN_ORG_NAME_PREFIXES.add(normalizedLabel);
                WHOIS_DOMAIN_ORG_NAME_PREFIXES.add(normalizedLabel.replace(" ", "-"));
                WHOIS_DOMAIN_ORG_NAME_PREFIXES.add(normalizedLabel.replace(" ", "_"));
            }

            for (String normalizedLabel : normalizedPhoneLabels) {
                WHOIS_DOMAIN_PHONE_PREFIXES.add(normalizedLabel);
                WHOIS_DOMAIN_PHONE_PREFIXES.add(normalizedLabel.replace(" ", "-"));
                WHOIS_DOMAIN_PHONE_PREFIXES.add(normalizedLabel.replace(" ", "_"));
            }
        }
    }
}
