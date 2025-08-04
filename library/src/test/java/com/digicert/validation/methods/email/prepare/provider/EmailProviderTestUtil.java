package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.methods.email.prepare.EmailDnsRecordName;

import java.util.Set;

public class EmailProviderTestUtil {
    static boolean containsEmailDnsRecordDomain(Set<EmailDnsRecordName> emails, String email, String domain) {
        return emails.stream()
                .anyMatch(m -> m.email().equals(email) && m.dnsRecordName().equals(domain));
    }
}
