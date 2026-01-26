package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.*;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.TextParseException;

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
                        new ChallengeValidationResponse(Optional.of("randomValue"), Set.of()));
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

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, defaultDomainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService, never()).getPrimaryDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService, never()).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomainWithLabel, response.dnsRecordName());
        assertTrue(response.errors().isEmpty());
    }

    @Test
    void testDnsValidationHandler_validate_HasMatchingRecord_withCustomLabel() throws TextParseException {
        String domainWithLabel = "_customlabel." + defaultDomain;

        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .domainLabel("_customlabel.")
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, domainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(domainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService, never()).getPrimaryDnsDetails(domainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(domainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService, never()).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(domainWithLabel, response.dnsRecordName());
        assertTrue(response.errors().isEmpty());
    }

    @Test
    void testDnsValidationHandler_validate_HasMatchingRecord_noLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, defaultDomain, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(getNotFoundMpicDnsDetails(defaultDomainWithLabel));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), anyString());
        verify(mpicDnsService).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(response.errors().isEmpty());
    }

    @Test
    void testDnsValidationHandler_validate_NonMatchingRecord() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, defaultDomainWithLabel, "some-other-value");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(getNotFoundMpicDnsDetails(defaultDomain));

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"));
        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
        assertEquals(2, response.errors().size());
        assertTrue(response.errors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        assertTrue(response.errors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
    }

    @Test
    void validateRequestToken_primaryReturnsNull() {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(null);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(null);
        when(mpicDnsService.mapToDcvErrorOrNull(any(), any())).thenReturn(DcvError.MPIC_INVALID_RESPONSE);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService, never()).getDnsDetails(anyString(), any(), anyString());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals(defaultDomain, response.domain());
        assertNull(response.mpicDetails());
        assertNull(response.dnsRecordName());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.MPIC_INVALID_RESPONSE));
    }

    @Test
    void validateRequestToken_multipleErrors() {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        List<DnsRecord> dnsRecords = List.of(new DnsRecord(DnsType.CNAME, defaultDomain, "randomValue", 3600, 0, ""));
        PrimaryDnsResponse primaryDnsResponse = new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.CNAME, defaultDomain, null);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);

        // Also configure the mock to return MpicDnsDetails when getDnsDetails is called for both domains
        // First domain with label returns MPIC_CORROBORATION_ERROR
        // Second domain without label returns DNS_LOOKUP_DOMAIN_NOT_FOUND
        MpicDnsDetails domainWithLabelErrorDetails = getMpicDnsDetailsWithError(defaultDomainWithLabel, DcvError.MPIC_CORROBORATION_ERROR, false);
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(domainWithLabelErrorDetails);
        MpicDnsDetails defaultDomainErrorDetails = getMpicDnsDetailsWithError(defaultDomain, DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND, true);
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(defaultDomainErrorDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertFalse(response.isValid());
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"));
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals(defaultDomain, response.domain());
        assertNull(response.mpicDetails());
        assertNull(response.dnsRecordName());
        assertNull(response.validRandomValue());
        assertNull(response.validRequestToken());
        assertEquals(2, response.errors().size());
        assertTrue(response.errors().contains(DcvError.MPIC_CORROBORATION_ERROR));
        assertTrue(response.errors().contains(DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND));
    }

    @Test
    void testDnsValidationHandler_validate_DnsEntriesNotFound() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue("randomValue")
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.RANDOM_VALUE)
                .build();

        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue")))
                .thenReturn(getMpicDnsDetailsWithError(defaultDomainWithLabel, DcvError.DNS_LOOKUP_IO_EXCEPTION, true));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue")))
                .thenReturn(getMpicDnsDetailsWithError(defaultDomain, DcvError.DNS_LOOKUP_IO_EXCEPTION, true));

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"));
        assertFalse(response.isValid());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isEmpty(response.validRequestToken()));
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(DcvError.DNS_LOOKUP_IO_EXCEPTION));
    }

    @Test
    void testDnsValidationHandler_validate_requestToken_withLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        List<DnsRecord> dnsRecords = List.of(new DnsRecord(DnsType.CNAME, defaultDomain, "randomValue", 3600, 0, ""));
        PrimaryDnsResponse primaryDnsResponse = new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.CNAME, defaultDomain, null);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, defaultDomainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService, never()).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomainWithLabel, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isNotEmpty(response.validRequestToken()));
        assertTrue(response.errors().isEmpty());
    }

    @Test
    void testDnsValidationHandler_validate_requestToken_withCustomLabel() throws TextParseException {
        String localDomainWithLabel = "_customlabel." + defaultDomain;

        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .domainLabel("_customlabel")
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        List<DnsRecord> dnsRecords = List.of(new DnsRecord(DnsType.CNAME, defaultDomain, "randomValue", 3600, 0, ""));
        PrimaryDnsResponse primaryDnsResponse = new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.CNAME, defaultDomain, null);
        when(mpicDnsService.getPrimaryDnsDetails(eq(localDomainWithLabel), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, localDomainWithLabel, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(localDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getPrimaryDnsDetails(localDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService, never()).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(localDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"));
        verify(mpicDnsService, never()).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(localDomainWithLabel, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isNotEmpty(response.validRequestToken()));
        assertTrue(response.errors().isEmpty());
    }

    @Test
    void testDnsValidationHandler_validate_requestToken_noLabel() throws TextParseException {
        DnsValidationRequest request = DnsValidationRequest.builder()
                .domain(defaultDomain)
                .requestTokenData(new BasicRequestTokenData("hashingKey", "hashingValue"))
                .dnsType(DnsType.CNAME)
                .challengeType(ChallengeType.REQUEST_TOKEN)
                .build();

        // Configure the mock to return a PrimaryDnsResponse when getPrimaryDnsDetails is called (both times)
        List<DnsRecord> dnsRecords = List.of(new DnsRecord(DnsType.CNAME, defaultDomain, "randomValue", 3600, 0, ""));
        PrimaryDnsResponse primaryDnsResponse = new PrimaryDnsResponse("primary-agent", AgentStatus.DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.CNAME, defaultDomain, null);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);
        when(mpicDnsService.getPrimaryDnsDetails(eq(defaultDomain), eq(DnsType.CNAME))).thenReturn(primaryDnsResponse);

        // Also configure the mock to return MpicDnsDetails when getDnsDetails is called
        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.CNAME, defaultDomain, "randomValue");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(getNotFoundMpicDnsDetails(defaultDomainWithLabel));
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), eq("randomValue"))).thenReturn(mpicDnsDetails);

        DnsValidationResponse response = dnsValidationHandler.validate(request);

        assertTrue(response.isValid());
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomainWithLabel, DnsType.CNAME);
        verify(mpicDnsService).getPrimaryDnsDetails(defaultDomain, DnsType.CNAME);
        verify(mpicDnsService).getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.CNAME), anyString());
        verify(mpicDnsService).getDnsDetails(eq(defaultDomain), eq(DnsType.CNAME), anyString());
        assertEquals(DnsType.CNAME, response.dnsType());
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomain, response.domain());
        assertEquals(defaultDomain, response.dnsRecordName());
        assertTrue(StringUtils.isEmpty(response.validRandomValue()));
        assertTrue(StringUtils.isNotEmpty(response.validRequestToken()));
        assertTrue(response.errors().isEmpty());
    }

    private static MpicDnsDetails getMpicDnsDetails(DnsType dnsType, String domainName, String dnsValue) {
        DnsRecord dnsRecord = new DnsRecord(
                dnsType,
                domainName,
                dnsValue,
                3600,
                0,
                "");
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", true, "secondary-2", true), null);
        return new MpicDnsDetails(mpicDetails,
                domainName,
                List.of(dnsRecord),
                null);
    }

    private static MpicDnsDetails getNotFoundMpicDnsDetails(String domain) {
        return getMpicDnsDetailsWithError(domain, null, true);
    }

    private static MpicDnsDetails getMpicDnsDetailsWithError(String domain, DcvError dcvError, boolean corroborated) {
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated), null);
        return new MpicDnsDetails(mpicDetails,
                domain,
                List.of(),
                dcvError);
    }

}