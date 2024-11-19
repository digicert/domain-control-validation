package com.digicert.validation.client.dns;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
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

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DnsClientTest {

    DcvConfiguration dcvConfiguration;

    @Mock
    ExtendedResolver extendedResolver;

    @Mock
    Lookup lookup;

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
            protected ExtendedResolver createResolver(String server, Integer dnsPort) {
                return extendedResolver;
            }

            @Override
            protected Lookup createLookup(String domain, int type) {
                return lookup;
            }
        };
    }

    static Stream<Arguments> provideDoubleTypeDnsData() {
        return Stream.of(
                Arguments.of("example.com.", DnsType.TXT, Type.TXT),
                Arguments.of("example.com.", DnsType.CNAME, Type.CNAME),
                Arguments.of("example.com.", DnsType.CAA, Type.CAA),
                Arguments.of("example.com.", DnsType.A, Type.A)
        );
    }

    @ParameterizedTest
    @MethodSource("provideDoubleTypeDnsData")
    void testGetDnsData_withDataReturned_happyPath(String domain, DnsType dnsType, int type) throws Exception {
        Record dnsRecord = Record.newRecord(Name.fromString(domain), type, DClass.IN);
        when(lookup.run()).thenReturn(new Record[]{dnsRecord});

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals("8.8.8.8", dnsData.serverWithData());
        assertEquals(domain, dnsData.domain());
        assertEquals(dnsType, dnsData.dnsType());
        assertFalse(dnsData.records().isEmpty());
        assertTrue(dnsData.servers().contains("8.8.8.8"));
    }

    static Stream<Arguments> provideSingleTypeDnsData() {
        return Stream.of(
                Arguments.of("example.com.", DnsType.TXT),
                Arguments.of("example.com.", DnsType.CNAME),
                Arguments.of("example.com.", DnsType.CAA)
        );
    }

    @ParameterizedTest
    @MethodSource("provideSingleTypeDnsData")
    void testGetDnsData_noDataReturned_happyPath(String domain, DnsType dnsType) {
        when(lookup.run()).thenReturn(null);

        DnsData dnsData = dnsClient.getDnsData(List.of(domain), dnsType);

        assertNotNull(dnsData);
        assertEquals("", dnsData.serverWithData());
        assertEquals(domain, dnsData.domain());
        assertEquals(dnsType, dnsData.dnsType());
        assertTrue(dnsData.records().isEmpty());
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