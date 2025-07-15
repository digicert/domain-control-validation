package com.digicert.validation.client.dns;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DnsClientTest {

    DcvConfiguration dcvConfiguration;

    @Mock
    ExtendedResolver extendedResolver;

    DnsClient dnsClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("8.8.8.8"))
                .dnsTimeout(5000)
                .build();
        DcvContext dcvContext = new DcvContext(dcvConfiguration);

        dnsClient = new DnsClient(dcvContext) {
            @Override
            protected ExtendedResolver createResolver(String server, Integer port) {
                return extendedResolver;
            }
        };
    }

    static Stream<Arguments> provideDoubleTypeDnsData() {
        return Stream.of(
                Arguments.of("example.com.", DnsType.TXT),
                Arguments.of("example.com.", DnsType.CNAME),
                Arguments.of("example.com.", DnsType.CAA),
                Arguments.of("example.com.", DnsType.A)
        );
    }

    @ParameterizedTest
    @MethodSource("provideDoubleTypeDnsData")
    void testGetDnsData_withDataReturned_happyPath(String domain, DnsType dnsType) throws Exception {
        Record dnsRecord = getDnsRecordFromType(domain, dnsType);

        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.NOERROR);
        when(responseMessage.getSection(Section.ANSWER)).thenReturn(List.of(dnsRecord));
        when(extendedResolver.send(any(Message.class))).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals("8.8.8.8", dnsData.serverWithData());
        assertEquals(domain, dnsData.domain());
        assertEquals(dnsType, dnsData.dnsType());
        assertFalse(dnsData.values().isEmpty());
        assertTrue(dnsData.servers().contains("8.8.8.8"));
    }

    @Test
    void testGetDnsData_withDataReturned_multipleEntries() throws Exception {
        String domain = "example.com";
        String expected = "\"testValue\" \"testValue2\"";

        org.xbill.DNS.Record txtRecord = getDnsRecordFromType(domain, DnsType.TXT);
        org.xbill.DNS.Record cnameRecord = getDnsRecordFromType(domain, DnsType.CNAME);

        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.NOERROR);
        when(responseMessage.getSection(Section.ANSWER)).thenReturn(List.of(txtRecord, cnameRecord));
        when(extendedResolver.send(any())).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), DnsType.TXT);

        assertNotNull(dnsData);
        assertEquals(2, dnsData.values().size());
        DnsValue dnsValue = dnsData.values().getFirst();
        assertTrue(dnsValue.getValue().startsWith(expected), "Error matching dns record. Expected: " + expected + ", Actual: " + dnsValue.getValue());
        assertEquals(DnsType.TXT, dnsData.dnsType());
        assertEquals(DnsType.TXT, dnsValue.getDnsType());
        assertEquals(domain, dnsData.domain());

        dnsValue = dnsData.values().getLast();
        assertEquals("http://cname.example.com.", dnsValue.getValue());
        assertEquals(DnsType.CNAME, dnsValue.getDnsType());
    }

    @Test
    void testGetDnsData_CaaRecordType_HappyPath() throws Exception {
        Record dnsRecord = getDnsRecordFromType("example.com", DnsType.CAA);

        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.NOERROR);
        when(responseMessage.getSection(Section.ANSWER)).thenReturn(List.of(dnsRecord));
        when(extendedResolver.send(any())).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of("example.com"), DnsType.CAA);

        assertNotNull(dnsData);
        assertEquals(DnsType.CAA, dnsData.dnsType());
        assertEquals("example.com", dnsData.domain());

        for (DnsValue dnsValue : dnsData.values()) {
            assertEquals(((CAARecord) dnsRecord).getFlags(), ((CaaValue) dnsValue).getFlag());
            assertEquals(((CAARecord) dnsRecord).getTag(), ((CaaValue) dnsValue).getTag());
            assertEquals(((CAARecord) dnsRecord).getValue(), dnsValue.getValue());
        }
    }

    static Stream<Arguments> provideSingleTypeDnsData() {
        return Stream.of(
                Arguments.of("example.com", DnsType.A),
                Arguments.of("example.com", DnsType.CAA),
                Arguments.of("example.com", DnsType.CNAME),
                Arguments.of("example.com", DnsType.MX),
                Arguments.of("example.com", DnsType.TXT),
                Arguments.of("example.com", DnsType.RRSIG),
                Arguments.of("example.com", DnsType.DS)
        );
    }

    @ParameterizedTest
    @MethodSource("provideSingleTypeDnsData")
    void testGetDnsData_domainNotFound(String domain, DnsType dnsType) throws IOException {
        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.NXDOMAIN);
        when(extendedResolver.send(any())).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals(dnsType, dnsData.dnsType());
        assertEquals(domain, dnsData.domain());
        assertEquals(List.of(), dnsData.values());
        assertEquals(DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND, dnsData.errors().stream().findFirst().get());
    }

    @ParameterizedTest
    @MethodSource("provideSingleTypeDnsData")
    void testGetDnsData_recordNotFound(String domain, DnsType dnsType) throws IOException {
        // Add some record that is not the one we are looking for
        String zoneName = domain + ".";
        Record dnsRecord = new DNAMERecord(Name.fromString(zoneName), DClass.IN, 3600, Name.fromString("http://example.com."));

        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.NXDOMAIN);
        when(responseMessage.getSection(Section.ANSWER)).thenReturn(List.of(dnsRecord));
        when(extendedResolver.send(any())).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals(dnsType, dnsData.dnsType());
        assertEquals(domain, dnsData.domain());
        assertEquals(List.of(), dnsData.values());
        assertEquals(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND, dnsData.errors().stream().findFirst().get());
    }

    @ParameterizedTest
    @MethodSource("provideSingleTypeDnsData")
    void testGetDnsData_serverError(String domain, DnsType dnsType) throws IOException {
        Message responseMessage = mock(Message.class);
        when(responseMessage.getRcode()).thenReturn(Rcode.SERVFAIL);
        when(extendedResolver.send(any())).thenReturn(responseMessage);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals(dnsType, dnsData.dnsType());
        assertEquals(domain, dnsData.domain());
        assertEquals(List.of(), dnsData.values());
        assertEquals(DcvError.DNS_LOOKUP_IO_EXCEPTION, dnsData.errors().stream().findFirst().get());
    }

    static Stream<Arguments> provideExceptionDnsData() {
        return Stream.of(
                Arguments.of(DnsType.A, new UnknownHostException("Intentional Exception"), DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION),
                Arguments.of(DnsType.CAA, new IOException("Intentional Exception"), DcvError.DNS_LOOKUP_IO_EXCEPTION),
                Arguments.of(DnsType.CNAME, new TextParseException("Intentional Exception"), DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION),
                Arguments.of(DnsType.RRSIG, new IOException("Intentional Exception", new TimeoutException("Intentional Timeout")),  DcvError.DNS_LOOKUP_TIMEOUT)
        );
    }

    @ParameterizedTest
    @MethodSource("provideExceptionDnsData")
    void testGetDnsData_exception(DnsType dnsType, Exception exception, DcvError dcvError) throws IOException {
        when(extendedResolver.send(any())).thenThrow(exception);

        DnsData dnsResponse = dnsClient.getDnsData(List.of("example.com"), dnsType);

        assertNotNull(dnsResponse);
        assertEquals(dnsType, dnsResponse.dnsType());
        assertEquals("example.com", dnsResponse.domain());
        assertEquals(List.of(), dnsResponse.values());
        assertEquals(dcvError, dnsResponse.errors().stream().findFirst().get());
    }

    private static Record getDnsRecordFromType(String domain, DnsType dnsType) throws TextParseException, UnknownHostException {
        return DnsRecordHelper.getDnsRecordFromType(domain, dnsType);
    }

    @ParameterizedTest
    @MethodSource("provideSingleTypeDnsData")
    void testGetDnsData_noDataReturned_happyPath(String domain, DnsType dnsType) {
        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals("", dnsData.serverWithData());
        assertEquals(domain, dnsData.domain());
        assertEquals(dnsType, dnsData.dnsType());
        assertTrue(dnsData.values().isEmpty());
        assertTrue(dnsData.servers().contains("8.8.8.8"));
    }

    @Test
    void testGetDnsData_noDomainsProvided_throwsException() {
        List<String> emptyDomains = Collections.emptyList();
        assertThrows(IllegalArgumentException.class, () -> dnsClient.getDnsData(emptyDomains, DnsType.TXT));
    }

    @Test
    void testGetDnsData_noDnsServersConfigured_throwsException() {
        DcvConfiguration emptyDnsServersConfig = mock(DcvConfiguration.class);
        when(emptyDnsServersConfig.getDnsServers()).thenReturn(Collections.emptyList());
        DcvContext emptyDnsServersContext = new DcvContext(emptyDnsServersConfig);
        DnsClient dnsClientWithNoServers = new DnsClient(emptyDnsServersContext);

        List<String> domains = List.of("example.com");
        assertThrows(IllegalArgumentException.class, () -> dnsClientWithNoServers.getDnsData(domains, DnsType.TXT));
    }
}