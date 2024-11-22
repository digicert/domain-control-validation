package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.challenges.BasicRandomValueValidator;
import com.digicert.validation.challenges.BasicRequestTokenValidator;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DnsValidationHandlerTest {

    private DnsClient dnsClient;

    private DnsValidationHandler dnsValidationHandler;

    @BeforeEach
    void setUp() {
        dnsClient = mock(DnsClient.class);

        DcvContext dcvContext = mock(DcvContext.class, RETURNS_DEEP_STUBS);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(new BasicRandomValueValidator());
        when(dcvContext.get(RequestTokenValidator.class)).thenReturn(new BasicRequestTokenValidator());
        when(dcvContext.get(DnsClient.class)).thenReturn(dnsClient);
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
        CNAMERecord cNameRecord = mock(CNAMERecord.class);
        when(cNameRecord.getTarget()).thenReturn(Name.fromString("randomValue.example.com."));
        String host = "8.8.8.8";
        DnsData dnsData = new DnsData(List.of(host), "example.com", DnsType.CNAME, List.of(cNameRecord),
                Set.of(), host);
        when(dnsClient.getDnsData(anyList(), eq(DnsType.CNAME))).thenReturn(dnsData);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        assertEquals("8.8.8.8", response.server());
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
        CNAMERecord cNameRecord = mock(CNAMERecord.class);
        when(cNameRecord.getTarget()).thenReturn(Name.fromString("nonMatchingValue.example.com."));
        String host = "8.8.8.8";
        DnsData dnsData = new DnsData(List.of(host), "example.com", DnsType.CNAME, List.of(cNameRecord),
                Set.of(), host);
        when(dnsClient.getDnsData(anyList(), eq(DnsType.CNAME))).thenReturn(dnsData);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("8.8.8.8", response.server());
        assertEquals("example.com", response.domain());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validToken()));
    }

    @Test
    void testDnsValidationHandler_getDnsRecordStringValue_DnsType_CNAME() throws TextParseException {
        CNAMERecord cNameRecord = mock(CNAMERecord.class);
        when(cNameRecord.getTarget()).thenReturn(Name.fromString("randomValue.example.com."));

        String result = dnsValidationHandler.getDnsRecordStringValue(cNameRecord, DnsType.CNAME);
        assertEquals("randomValue.example.com.", result);
    }

    @Test
    void testDnsValidationHandler_getDnsRecordStringValue_DnsType_TXT() {
        TXTRecord txtRecord = mock(TXTRecord.class);
        when(txtRecord.getStrings()).thenReturn(List.of("randomValue", "notMatchingValue", "notMatchingValue"));

        String result = dnsValidationHandler.getDnsRecordStringValue(txtRecord, DnsType.TXT);

        assertEquals("randomValue\nnotMatchingValue\nnotMatchingValue", result);
    }

    @Test
    void testDnsValidationHandler_getDnsRecordStringValue_DnsType_CAA() {
        CAARecord caaRecord = mock(CAARecord.class);
        when(caaRecord.getValue()).thenReturn("caa-record-value");

        String result = dnsValidationHandler.getDnsRecordStringValue(caaRecord, DnsType.CAA);

        assertEquals("caa-record-value", result);
    }

    @Test
    void testDnsValidationHandler_validate_requestToken() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain("example.com")
                .tokenKey("tokenKey")
                .tokenValue("tokenValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();
        CNAMERecord cNameRecord = mock(CNAMERecord.class);
        when(cNameRecord.getTarget()).thenReturn(Name.fromString("randomValue.example.com."));
        String host = "8.8.8.8";
        DnsData dnsData = new DnsData(List.of(host), "example.com", DnsType.CNAME, List.of(cNameRecord),
                Set.of(), host);
        when(dnsClient.getDnsData(anyList(), eq(DnsType.CNAME))).thenReturn(dnsData);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        assertEquals("8.8.8.8", response.server());
        assertEquals("example.com", response.domain());
    }
}