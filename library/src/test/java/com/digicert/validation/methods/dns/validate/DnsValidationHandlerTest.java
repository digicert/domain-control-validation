package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.*;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DnsValidationHandlerTest {

    private MpicDnsService mpicDnsService;

    private DnsValidationHandler dnsValidationHandler;

    @BeforeEach
    void setUp() {
        mpicDnsService = mock(MpicDnsService.class);

        DcvContext dcvContext = mock(DcvContext.class, RETURNS_DEEP_STUBS);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(new BasicRandomValueValidator());
        when(dcvContext.get(RequestTokenValidator.class)).thenReturn(new BasicRequestTokenValidator());
        when(dcvContext.get(MpicDnsService.class)).thenReturn(mpicDnsService);
        when(dcvContext.getDcvConfiguration().getDnsDomainLabel()).thenReturn("_testLabel");

        dnsValidationHandler = new DnsValidationHandler(dcvContext);
    }

    @Test
    void testDnsValidationHandler_validate_HasMatchingRecord() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain("example.com")
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, true, "randomValue");
        when(mpicDnsService.getDnsDetails(anyList(), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals("example.com", response.domain());
    }


    @Test
    void testDnsValidationHandler_validate_NonMatchingRecord() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain("example.com")
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, true, "some-other-value");
        when(mpicDnsService.getDnsDetails(anyList(), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals("example.com", response.domain());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
    }

    @Test
    void testDnsValidationHandler_validate_requestToken() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain("example.com")
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, false, "randomValue");
        when(mpicDnsService.getDnsDetails(anyList(), eq(DnsType.CNAME))).thenReturn(mpicDnsDetails);


        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals("example.com", response.domain());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
    }

    private static MpicDnsDetails getMpicDnsDetails(DnsType dnsType, boolean corroborated, String dnsValue) {
        DnsRecord dnsRecord = new DnsRecord(
                dnsType,
                "randomValue.example.com.",
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
                "example.com",
                List.of(dnsRecord),
                null);
    }

}