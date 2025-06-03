package com.digicert.validation.mpic;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;

public interface MpicClientInterface {
    MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType);

    MpicFileResponse getMpicFileResponse(String fileUrl);

    default Boolean shouldEnforceCorroboration() {
        return true;
    }
}
