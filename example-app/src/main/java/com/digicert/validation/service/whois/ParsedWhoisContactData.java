package com.digicert.validation.service.whois;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * Represents parsed WHOIS contact data.
 * <p>
 * This class encapsulates the contact information retrieved from a WHOIS lookup.
 */
@Getter
@Setter
@AllArgsConstructor
public class ParsedWhoisContactData {

    /**
     * The type of the contact data.
     * <p>
     * This field indicates the type of contact information stored in this instance.
     */
    private String type;

    /**
     * The email address of the contact.
     * <p>
     * This field stores the email address associated with the contact.
     * 
     */
    private String email;

    /**
     * The organization name of the contact.
     * <p>
     * This field contains the name of the organization that the contact is associated with.
     */
    private String orgName;

    /**
     * The phone number of the contact.
     * <p>
     * This field holds the phone number of the contact.
     */
    private String phone;

    /**
     * Constructs a new ParsedWhoisContactData with the specified type.
     *
     * @param type the type of the contact data
     */
    public ParsedWhoisContactData(String type) {
        this(type, null, null, null);
    }
}