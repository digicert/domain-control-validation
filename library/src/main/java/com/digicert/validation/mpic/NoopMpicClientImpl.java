package com.digicert.validation.mpic;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import org.apache.commons.lang3.NotImplementedException;

/**
 * No-op implementation of the MpicClientInterface.
 * This is a placeholder implementation that throws exceptions if any methods are called.
 * <p>
 * It is expected that users of the DCV library will provide their own implementation
 */
public class NoopMpicClientImpl implements MpicClientInterface {

    @Override
    public MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType, String challengeValue) {
        throw new NotImplementedException("NoopMpicClientImpl is not meant to be used and does not support DNS requests - define your own MpicClientInterface object");
    }

    @Override
    public PrimaryDnsResponse getPrimaryOnlyDnsResponse(String domain, DnsType dnsType) {
        throw new NotImplementedException("NoopMpicClientImpl is not meant to be used and does not support DNS requests - define your own MpicClientInterface object");
    }

    @Override
    public MpicFileResponse getMpicFileResponse(String fileUrl, String challengeValue) {
        throw new NotImplementedException("NoopMpicClientImpl is not meant to be used and does not support File requests - define your own MpicClientInterface object");
    }

    @Override
    public PrimaryFileResponse getPrimaryOnlyFileResponse(String fileUrl) {
        throw new NotImplementedException("NoopMpicClientImpl is not meant to be used and does not support File requests - define your own MpicClientInterface object");
    }
}
