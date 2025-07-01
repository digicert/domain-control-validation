package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.*;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DnsValidationHandlerTest {

    private final String defaultDomain = "example.com";
    private final String defaultDomainWithLabel = "_testLabel.example.com";
    private MpicDnsService mpicDnsService;

    private DnsValidationHandler dnsValidationHandler;

    @BeforeEach
    void setUp() {
        mpicDnsService = mock(MpicDnsService.class);

        DcvContext dcvContext = mock(DcvContext.class, RETURNS_DEEP_STUBS);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(new BasicRandomValueValidator());
        when(dcvContext.get(RequestTokenValidator.class))
                .thenReturn((requestTokenData, textBody) ->
                        new ChallengeValidationResponse(Optional.of("some-request-response"), Set.of()));
        when(dcvContext.get(MpicDnsService.class)).thenReturn(mpicDnsService);
        when(dcvContext.getDcvConfiguration().getDnsDomainLabel()).thenReturn("_testLabel.");

        dnsValidationHandler = new DnsValidationHandler(dcvContext);
    }

    @Test
    void testDnsValidationHandler_validate_HasMatchingRecord_withLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, true, defaultDomainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getDnsDetails(defaultDomain, DnsType.CNAME);
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomainWithLabel, response.dnsRecordName());
    }

    @Test
    void testDnsValidationHandler_validate_HasMatchingRecord_noLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, true, defaultDomain, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(getNotFoundMpicDnsDetails(defaultDomainWithLabel));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(defaultDomain, DnsType.CNAME);
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
    }

    @Test
    void testDnsValidationHandler_validate_NonMatchingRecord() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, true, defaultDomainWithLabel, "some-other-value");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(getNotFoundMpicDnsDetails(defaultDomain));

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
    }

    @Test
    void testDnsValidationHandler_validate_DnsEntriesNotFound() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME)))
                .thenReturn(getErrorMpicDnsDetails(defaultDomainWithLabel));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME)))
                .thenReturn(getErrorMpicDnsDetails(defaultDomain));

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
    }

    @Test
    void testDnsValidationHandler_validate_requestToken_withLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, false, defaultDomainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getDnsDetails(defaultDomain, DnsType.CNAME);
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomainWithLabel, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isNotEmpty(response.validRequestToken()));
    }

    @Test
    void testDnsValidationHandler_validate_requestToken_noLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, false, defaultDomain, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME)))
                .thenReturn(getNotFoundMpicDnsDetails(defaultDomainWithLabel));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(defaultDomain, DnsType.CNAME);
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isNotEmpty(response.validRequestToken()));
    }

    private static MpicDnsDetails getMpicDnsDetails(DnsType dnsType, boolean corroborated, String domainName, String dnsValue) {
        DnsRecord dnsRecord = new DnsRecord(
                dnsType,
                domainName,
                dnsValue,
                3600,
                0,
                "");
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated));
        return new MpicDnsDetails(mpicDetails,
                domainName,
                List.of(dnsRecord),
                null);
    }

    private static MpicDnsDetails getNotFoundMpicDnsDetails(String domain) {
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", true, "secondary-2", true));
        return new MpicDnsDetails(mpicDetails,
                domain,
                List.of(),
                null);
    }

    private static MpicDnsDetails getErrorMpicDnsDetails(String domain) {
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", true, "secondary-2", true));
        return new MpicDnsDetails(mpicDetails,
                domain,
                List.of(),
                DcvError.DNS_LOOKUP_IO_EXCEPTION);
    }

}