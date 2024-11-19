package com.digicert.validation.service.whois;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BasicWhoisParserTest {
    private BasicWhoisParser parser;

    @BeforeEach
    void setUp() {
        parser = new BasicWhoisParser();
    }

    @Test
    void testParseWhoisRecord_withEmails() {
        String rawWhoisData = """
                Registrant Email: registrant@example.com
                Tech Email: tech@example.com
                Admin Email: admin@example.com
                """;

        ParsedWhoisData parsedData = parser.parseWhoisRecord(rawWhoisData);

        Set<String> expectedEmails = Set.of("registrant@example.com", "tech@example.com", "admin@example.com");
        assertEquals(expectedEmails, parsedData.emails());

        List<ParsedWhoisContactData> contacts = parsedData.domainContacts();
        assertEquals(5, contacts.size());

        ParsedWhoisContactData adminContact = contacts.get(0);
        assertEquals("admin@example.com", adminContact.getEmail());

        ParsedWhoisContactData techContact = contacts.get(1);
        assertEquals("tech@example.com", techContact.getEmail());

        ParsedWhoisContactData registrantContact = contacts.get(3);
        assertEquals("registrant@example.com", registrantContact.getEmail());
    }

    @Test
    void testParseWhoisRecord_withOrgNames() {
        String rawWhoisData = """
                Admin Organization: Admin Org
                Tech Organization: Tech Org
                Registrant Organization: Registrant Org
                Org Name: Organization Name
                """;

        ParsedWhoisData parsedData = parser.parseWhoisRecord(rawWhoisData);

        List<ParsedWhoisContactData> contacts = parsedData.domainContacts();
        assertEquals(5, contacts.size());

        ParsedWhoisContactData adminContact = contacts.get(0);
        assertEquals("Admin Org", adminContact.getOrgName());

        ParsedWhoisContactData techContact = contacts.get(1);
        assertEquals("Tech Org", techContact.getOrgName());

        ParsedWhoisContactData registrantContact = contacts.get(3);
        assertEquals("Registrant Org", registrantContact.getOrgName());

        ParsedWhoisContactData recordContact = contacts.get(4);
        assertEquals("Organization Name", recordContact.getOrgName());
    }

    @Test
    void testParseWhoisRecord_withPhones() {
        String rawWhoisData = """
                Registrant Phone: +1-800-555-1234
                Tech Phone: +1-800-555-5678
                Admin Phone: +1-800-555-8765
                """;

        ParsedWhoisData parsedData = parser.parseWhoisRecord(rawWhoisData);

        List<ParsedWhoisContactData> contacts = parsedData.domainContacts();
        assertEquals(5, contacts.size());

        ParsedWhoisContactData adminContact = contacts.getFirst();
        assertEquals("administrative", contacts.get(0).getType());
        assertEquals("+1-800-555-8765", adminContact.getPhone());

        ParsedWhoisContactData techContact = contacts.get(1);
        assertEquals("technical", contacts.get(1).getType());
        assertEquals("+1-800-555-5678", techContact.getPhone());

        ParsedWhoisContactData registrantContact = contacts.get(3);
        assertEquals("registrant", contacts.get(3).getType());
        assertEquals("+1-800-555-1234", registrantContact.getPhone());
    }

    @Test
    void testGetName() {
        assertEquals("basic", parser.getName());
    }

    @Test
    void testGetParsableEmailLabels() {
        Set<String> expectedLabels = new HashSet<>(Set.of(
                "registrant email",
                "registrant contact email",
                "courriel registrant",
                "tec email",
                "tech email",
                "technical email",
                "technical contact email",
                "courriel contact tech1",
                "courriel contact tech2",
                "ac email",
                "adm email",
                "admin email",
                "admin contact email",
                "administrative email",
                "administrative contact email",
                "courriel contact admin"
        ));

        Set<String> actualLabels = parser.getParsableEmailLabels();

        Set<String> normalizedExpectedLabels = new HashSet<>();
        for (String label : expectedLabels) {
            normalizedExpectedLabels.add(label);
            normalizedExpectedLabels.add(label.replace("email", "e-mail"));
            normalizedExpectedLabels.add(label.replace(" ", "-"));
            normalizedExpectedLabels.add(label.replace(" ", "-").replace("email", "e-mail"));
            normalizedExpectedLabels.add(label.replace(" ", "_"));
            normalizedExpectedLabels.add(label.replace(" ", "_").replace("email", "e-mail"));
        }

        assertEquals(normalizedExpectedLabels, actualLabels);
    }
}