package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.methods.dns.validate.MpicDnsDetails;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static com.digicert.validation.mpic.api.AgentStatus.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MpicDnsServiceTest {

    private DcvContext dcvContext;
    private MpicClientInterface mpicClient;
    private MpicDnsService mpicDnsService;

    @BeforeEach
    void setUp() {
        dcvContext = mock(DcvContext.class);
        mpicClient = mock(MpicClientInterface.class);
        when(dcvContext.get(MpicClientInterface.class)).thenReturn(mpicClient);
        mpicDnsService = new MpicDnsService(dcvContext);
    }

    private MpicDnsResponse createMpicDnsResponse(PrimaryDnsResponse primary,
                                                  List<SecondaryDnsResponse> secondary,
                                                  MpicStatus mpicStatus) {
        return new MpicDnsResponse(primary, secondary, mpicStatus, 2, null);
    }

    @Test
    void returnsInvalidResponseWhenMpicStatusIsError() {
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, List.of(), DnsType.TXT, "example.com");
        MpicDnsResponse response = createMpicDnsResponse(primary, Collections.emptyList(), MpicStatus.ERROR);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);
        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);
        assertEquals(DcvError.MPIC_INVALID_RESPONSE, details.dcvError());
    }

    @Test
    void returnsRecordNotFoundErrorWhenDnsRecordsIsNull() {
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, null, DnsType.TXT, "example.com");
        MpicDnsResponse response = createMpicDnsResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);

        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);
        assertEquals(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND, details.dcvError());
    }

    @Test
    void returnsRecordNotFoundErrorWhenDnsRecordsIsEmpty() {
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, Collections.emptyList(), DnsType.TXT, "example.com");
        MpicDnsResponse response = createMpicDnsResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);

        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);
        assertEquals(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND, details.dcvError());
    }

    @Test
    void returnsCorroborationErrorWhenShouldEnforceCorroborationAndStatusNonCorroborated() {
        List<DnsRecord> dnsRecords = List.of(new DnsRecord(DnsType.TXT, "example.com", "record1", 0, 0, ""));
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.TXT, "example.com");
        MpicDnsResponse response = createMpicDnsResponse(primary, Collections.emptyList(), MpicStatus.NON_CORROBORATED);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);
        when(mpicClient.shouldEnforceCorroboration()).thenReturn(true);

        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);
        assertEquals(DcvError.MPIC_CORROBORATION_ERROR, details.dcvError());
    }

    @Test
    void returnsValidWhenAllIsGood() {
        DnsRecord record1 = new DnsRecord(DnsType.TXT, "example.com", "record1", 0, 0, "");
        DnsRecord record2 = new DnsRecord(DnsType.TXT, "example.com", "record2", 0, 0, "");
        List<DnsRecord> dnsRecords = List.of(record1, record2);
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, dnsRecords, DnsType.TXT, "example.com");
        SecondaryDnsResponse secondary = new SecondaryDnsResponse("agent2", DNS_LOOKUP_SUCCESS, true, dnsRecords);
        MpicDnsResponse response = createMpicDnsResponse(primary, List.of(secondary), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);
        when(mpicClient.shouldEnforceCorroboration()).thenReturn(false);

        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);

        assertNull(details.dcvError());
        assertTrue(details.mpicDetails().corroborated());
        assertEquals(dnsRecords, details.dnsRecords());
        assertEquals("example.com", details.domain());
        assertNotNull(details.mpicDetails());
        assertEquals("agent1", details.mpicDetails().primaryAgentId());
        assertEquals(1, details.mpicDetails().secondaryServersChecked());
        assertEquals(1, details.mpicDetails().secondaryServersCorroborated());
        assertTrue(details.mpicDetails().agentIdToCorroboration().get("agent2"));
    }

    @Test
    void returnsFirstValidOrFirstErrorForMultipleDomains() {
        // First domain returns error, second is valid
        PrimaryDnsResponse errorPrimary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_TIMEOUT, List.of(), DnsType.TXT, "error.com");
        MpicDnsResponse errorResponse = createMpicDnsResponse(errorPrimary, Collections.emptyList(), MpicStatus.CORROBORATED);

        List<DnsRecord> validDnsRecords = List.of(new DnsRecord(DnsType.TXT, "example.com", "record1", 0, 0, ""));
        PrimaryDnsResponse validPrimary = new PrimaryDnsResponse("agent1", DNS_LOOKUP_SUCCESS, validDnsRecords, DnsType.TXT, "valid.com");
        MpicDnsResponse validResponse = createMpicDnsResponse(validPrimary, Collections.emptyList(), MpicStatus.CORROBORATED);

        when(mpicClient.getMpicDnsResponse("error.com", DnsType.TXT)).thenReturn(errorResponse);
        when(mpicClient.getMpicDnsResponse("valid.com", DnsType.TXT)).thenReturn(validResponse);
        when(mpicClient.shouldEnforceCorroboration()).thenReturn(false);

        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("error.com", "valid.com"), DnsType.TXT);
        assertNull(details.dcvError());
        assertEquals(validDnsRecords, details.dnsRecords());
        assertTrue(details.mpicDetails().corroborated());

        // Now, both error
        when(mpicClient.getMpicDnsResponse("valid.com", DnsType.TXT)).thenReturn(errorResponse);
        MpicDnsDetails errorDetails = mpicDnsService.getDnsDetails(List.of("error.com", "valid.com"), DnsType.TXT);
        assertEquals(DcvError.DNS_LOOKUP_TIMEOUT, errorDetails.dcvError());
    }

    @ParameterizedTest
    @MethodSource("agentStatusToErrorMapping")
    void mapsDifferentAgentStatusesToCorrectDcvErrors(AgentStatus agentStatus, DcvError expectedError) {
        // Setup
        PrimaryDnsResponse primary = new PrimaryDnsResponse("agent1", agentStatus, List.of(), DnsType.TXT, "example.com");
        MpicDnsResponse response = createMpicDnsResponse(primary, Collections.emptyList(), MpicStatus.CORROBORATED);
        when(mpicClient.getMpicDnsResponse("example.com", DnsType.TXT)).thenReturn(response);

        // Execute
        MpicDnsDetails details = mpicDnsService.getDnsDetails(List.of("example.com"), DnsType.TXT);

        // Verify
        assertEquals(expectedError, details.dcvError());
        assertTrue(details.mpicDetails().corroborated());
        assertEquals("example.com", details.domain());
        assertEquals(List.of(), details.dnsRecords());
    }

    static Stream<Arguments> agentStatusToErrorMapping() {
        return Stream.of(
                Arguments.of(DNS_LOOKUP_BAD_REQUEST, DcvError.DNS_LOOKUP_BAD_REQUEST),
                Arguments.of(DNS_LOOKUP_TIMEOUT, DcvError.DNS_LOOKUP_TIMEOUT),
                Arguments.of(DNS_LOOKUP_IO_EXCEPTION, DcvError.DNS_LOOKUP_IO_EXCEPTION),
                Arguments.of(DNS_LOOKUP_DOMAIN_NOT_FOUND, DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND),
                Arguments.of(DNS_LOOKUP_RECORD_NOT_FOUND, DcvError.DNS_LOOKUP_RECORD_NOT_FOUND),
                Arguments.of(DNS_LOOKUP_TEXT_PARSE_EXCEPTION, DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION),
                Arguments.of(DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION, DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION),

                // This should never happen, but we handle it gracefully
                Arguments.of(FILE_BAD_REQUEST, DcvError.MPIC_INVALID_RESPONSE)
        );
    }
}