package com.digicert.validation.mpic;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;

/**
 * Interface for MPIC (Multi-Perspective Corroboration) client operations.
 * This interface defines methods to retrieve MPIC DNS responses and file responses.
 * <p>
 * This interface also provides a default method to determine if corroboration enforcement
 * is required, which must be true after the 09/15/2025 deadline for MPIC implemenation.
 */
public interface MpicClientInterface {
    MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType);

    MpicFileResponse getMpicFileResponse(String fileUrl);

    default Boolean shouldEnforceCorroboration() {
        return true;
    }
}
