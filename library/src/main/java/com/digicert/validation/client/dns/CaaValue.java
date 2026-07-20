package com.digicert.validation.client.dns;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Represents a DNS CAA (Certification Authority Authorization) record.
 * This record specifies which certificate authorities are allowed to issue certificates for a domain.
 */
@Data
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
public class CaaValue extends DnsValue {
    private String tag;
    private int flag;

    /** Creates a new {@code CaaValue} with all fields set to their default values. */
    public CaaValue() {
    }
}
