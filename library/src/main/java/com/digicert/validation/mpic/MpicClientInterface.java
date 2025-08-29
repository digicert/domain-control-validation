package com.digicert.validation.mpic;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;

/**
 * Interface for MPIC (Multi-Perspective Corroboration) client operations.
 * This interface defines methods to retrieve MPIC DNS responses and file responses.
 * <p>
 * This interface also provides a default method to determine if corroboration enforcement
 * is required, which must be true after the 09/15/2025 deadline for MPIC implemenation.
 */
public interface MpicClientInterface {

    /**
     * Retrieves the MPIC DNS response for a given domain, DNS type, and challenge value.
     * @param domain            The domain to query.
     * @param dnsType           The type of DNS record to query (e.g., TXT, CNAME).
     * @param challengeValue    The challenge value to look for in the DNS records. This can be null if not applicable.
     * @return
     */
    MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType, String challengeValue);

    /**
     * Retrieves the primary-only DNS response for a given domain and DNS type. NO CORROBORATION Check is done.
     * @param domain    The domain to query.
     * @param dnsType   The type of DNS record to query (e.g., TXT, CNAME).
     * @return          The primary DNS response.
     */
    PrimaryDnsResponse getPrimaryOnlyDnsResponse(String domain, DnsType dnsType);

    /**
     * Retrieves the MPIC file response for a given file URL and challenge value.
     * @param fileUrl             The URL of the file to query.
     * @param challengeValue      The challenge value to look for in the file content. This can be null if not applicable.
     * @return MpicFileResponse   The MPIC file response.
     */
    MpicFileResponse getMpicFileResponse(String fileUrl, String challengeValue);

    /**
     * Retrieves a primary-only file response for a given file URL. NO CORROBORATION Check is done.
     * @param fileUrl             The URL of the file to query.
     * @return MpicFileResponse   The MPIC file response.
     */
    PrimaryFileResponse getPrimaryOnlyFileResponse(String fileUrl);

    default Boolean shouldEnforceCorroboration() {
        return true;
    }
}
