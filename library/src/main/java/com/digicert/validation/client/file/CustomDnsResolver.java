package com.digicert.validation.client.file;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.enums.DnsType;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.xbill.DNS.ARecord;

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
     * resolution logic. It uses the DnsClient to perform the A record DNS lookup.
     * The A records are then converted to InetAddress objects, which are returned as the
     * result. If the DNS lookup fails or an error occurs, an UnknownHostException is thrown with a detailed
     * error message.
     *
     * @param host The host name to resolve.
     * @return An array of InetAddress objects for the given host name.
     * @throws UnknownHostException If the host name cannot be resolved.
     */
    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        try {
            return dnsClient.getDnsData(List.of(host), DnsType.A)
                    .records()
                    .stream()
                    .filter(ARecord.class::isInstance)
                    .map(ARecord.class::cast)
                    .map(ARecord::getAddress)
                    .toArray(InetAddress[]::new);
        } catch (Exception e) {
            throw new UnknownHostException("Failed to resolve host: " + host + " due to " + e.getMessage());
        }
    }
}