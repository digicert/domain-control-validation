package com.digicert.validation.client.file;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.client.dns.DnsValue;
import com.digicert.validation.enums.DnsType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.socket.PortFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Name;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class CustomDnsResolverTest {

    private static ClientAndServer mockServer;

    @Mock
    private DnsClient dnsClient;

    @Mock
    private DcvContext dcvContext;

    private CustomDnsResolver customDnsResolver;

    @BeforeAll
    public static void startServer() {
        mockServer = ClientAndServer.startClientAndServer(PortFactory.findFreePort());
    }

    @AfterAll
    public static void stopServer() {
        mockServer.stop();
    }

    @BeforeEach
    public void setUp() {
        mockServer.reset();
        MockitoAnnotations.openMocks(this);

        // Mock the behavior of dcvContext to return the mocked dnsClient
        when(dcvContext.get(DnsClient.class)).thenReturn(dnsClient);

        // Explicitly create an instance of CustomDnsResolver with the mocked dcvContext
        customDnsResolver = new CustomDnsResolver(dcvContext);
    }

    @Test
    void testCustomDnsResolver_resolve() throws Exception {
        String domain = "digicert.com";
        String digicertIp = "64.78.193.234";
        DnsValue dnsValue = new DnsValue(DnsType.A, domain, digicertIp, 3600);
        DnsData expectedDnsData = new DnsData(List.of("dnsServer"), domain, DnsType.A, List.of(dnsValue), Set.of(), "dnsServer");
        when(dnsClient.getDnsData(List.of(domain), DnsType.A)).thenReturn(expectedDnsData);

        InetAddress[] actualResult = customDnsResolver.resolve(domain);

        assertNotNull(actualResult);
        assertEquals(1, actualResult.length);
        assertEquals(digicertIp, actualResult[0].getHostAddress());
    }

    @Test
    void testCustomDnsResolver_resolveWithException() {
        String domain = "digicert.com";
        when(dnsClient.getDnsData(List.of(domain), DnsType.A)).thenThrow(new RuntimeException("Failed to get DNS data"));

        UnknownHostException exception = assertThrows(UnknownHostException.class, () -> customDnsResolver.resolve(domain));
        assertTrue(exception.getMessage().contains("Failed to resolve host: digicert.com due to Failed to get DNS data"));
    }
}