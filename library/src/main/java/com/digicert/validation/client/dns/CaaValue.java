package com.digicert.validation.client.dns;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * Represents a DNS CAA (Certification Authority Authorization) record.
 * This record specifies which certificate authorities are allowed to issue certificates for a domain.
 */
@Data
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
public class CaaValue extends DnsValue {
    private String tag;
    private int flag;
}
