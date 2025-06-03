package com.digicert.validation.mpic;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import org.apache.commons.lang3.NotImplementedException;

public class NoopMpicClientImpl implements MpicClientInterface {

    @Override
    public MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType) {
        throw new NotImplementedException("NoopMpicClientImpl does not support DNS requests");
    }

    @Override
    public MpicFileResponse getMpicFileResponse(String fileUrl) {
        throw new NotImplementedException("NoopMpicClientImpl does not support DNS requests");
    }
}
