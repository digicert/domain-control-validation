package com.digicert.validation.service.whois;

/**
 * Interface for parsing WHOIS records.
 */
public interface WhoisParser {

    /**
     * Parses the given raw WHOIS data and returns the parsed WHOIS data.
     * <p>
     * Provide an implementation that takes a raw WHOIS data string as input and processes it to extract meaningful information
     * such as registrant details, administrative contacts, and technical contacts.
     *
     * @param rawWhoIsData the raw WHOIS data as a string
     * @return the parsed WHOIS data
     */
    ParsedWhoisData parseWhoisRecord(String rawWhoIsData);
}