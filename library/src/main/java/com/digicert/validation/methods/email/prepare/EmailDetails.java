package com.digicert.validation.methods.email.prepare;

import com.digicert.validation.mpic.MpicDetails;

import java.util.Set;

/**
 * Represents the results of the DNS lookup for email validation.
 * <p>
 * This record encapsulates the necessary details required for preparing an email validation process.
 * The emails field represents the emails found at the target domain for the given record type and any associated DNS record,
 * which can be used to validate the domain. The mpicDetails field represents a summary of the MPIC details, which includes
 * the MPIC response, the domain being validated, and any errors encountered while retrieving the MPIC response.
 *
 * @param emails      The emails found at the target domain and the DNS record name used to retrieve the email.
 * @param mpicDetails A summary of the MPIC lookup details.
 */
public record EmailDetails(Set<EmailDnsRecordName> emails,
                           MpicDetails mpicDetails){
}
