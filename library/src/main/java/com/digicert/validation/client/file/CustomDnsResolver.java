package com.digicert.validation.client.file;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.enums.DnsType;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.bouncycastle.util.IPAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * CustomDnsResolver is an implementation of the DnsResolver interface that utilizes a DnsClient
 * to perform DNS queries. It specifically processes A records and converts them into InetAddress objects.
 * <p>
 * According to the BR's, DNS resolution must be conducted by DNS servers managed by the CA. This library
 * facilitates this requirement by using the DNS servers specified in the DCV configuration.
 */
public class CustomDnsResolver extends SystemDefaultDnsResolver {

    /** The DnsClient used to resolve DNS queries. */
    private final DnsClient dnsClient;

    /**
     * Constructs a CustomDnsResolver with the specified DcvContext. The Context is used to retrieve the
     * DnsClient dependency needed to perform DNS queries.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public CustomDnsResolver(DcvContext dcvContext) {
        dnsClient = dcvContext.get(DnsClient.class);
    }

    /**
     * Resolves the given host name to an array of InetAddress objects using the DnsClient.
     * <p>
     * This method overrides the resolve method of the SystemDefaultDnsResolver to provide custom DNS
     * resolution logic. If the host is already an IP address literal (IPv4 or IPv6), it is resolved
     * directly via the system resolver without performing a DNS lookup — DNS A-record queries for bare
     * IP addresses are meaningless and will always fail. The check is performed using
     * {@link IPAddress#isValid(String)}, a pure-parser check that performs no DNS queries and handles
     * both IPv4 and IPv6 literals correctly regardless of canonical form.
     * <p>
     * For domain names, the DnsClient performs an A-record lookup using the CA-managed DNS servers
     * required by the CA/Browser Forum Baseline Requirements.
     *
     * @param host The host name (or IP address literal) to resolve.
     * @return An array of InetAddress objects for the given host.
     * @throws UnknownHostException If the host name cannot be resolved.
     */
    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        // IP address literals need no DNS lookup — delegate directly to the system resolver.
        if (IPAddress.isValid(host)) {
            return super.resolve(host);
        }

        try {

            return dnsClient.getDnsData(List.of(host), DnsType.A)
                    .values()
                    .stream()
                    .filter(value -> value.getDnsType() == DnsType.A)
                    .map(value -> {
                        try {
                            return InetAddress.getByName(value.getValue());
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to convert DNS value to InetAddress: " + value.getValue(), e);
                        }
                    })
                    .toArray(InetAddress[]::new);
        } catch (Exception e) {
            throw new UnknownHostException("Failed to resolve host: " + host + " due to " + e.getMessage());
        }
    }
}