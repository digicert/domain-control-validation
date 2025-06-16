package com.digicert.validation.client.dns;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * DnsClient is responsible for querying DNS records from specified DNS servers.
 * It supports various DNS record types and handles errors encountered during the DNS query process.
 * <p>
 * This class uses the configuration provided by {@link DcvConfiguration} to initialize DNS servers, timeout and retries.
 * The DnsClient class is designed to be flexible and robust, allowing for easy integration with different DNS servers
 * and handling various DNS record types such as A, CNAME, TXT, and CAA. It also includes error handling mechanisms to
 * manage common DNS query issues, ensuring reliable DNS data retrieval.
 * </p>
 */
@Slf4j
public class DnsClient {

    /**
     * The list of DNS servers to query.
     * <p>
     * This list is initialized from the {@link DcvConfiguration} and contains the DNS servers that the client will
     * query for DNS records. The order of the servers in the list can affect the query process, as the client will
     * attempt to query each server in sequence until it receives a valid response or exhausts the list.
     */
    private final List<String> dnsServers;

    /**
     * The timeout for DNS queries in milliseconds.
     * <p>
     * This timeout value, specified in milliseconds, determines how long the client will wait for a response from a
     * DNS server before considering the query to have failed.
     */
    private final int dnsTimeout;

    /**
     * The number of retries for DNS queries.
     * <p>
     * This value specifies the number of times the client will retry a DNS query if it does not receive a valid response
     * within the specified timeout period.
     */
    private final int dnsRetries;

    /** The log level used for logging errors related to domain control validation (DCV). */
    private final Level logLevelForErrors;

    /**
     * Constructs a new DnsClient with the specified configuration.
     * <p>
     * This constructor initializes the DnsClient using the provided {@link DcvContext}, which contains the necessary
     * configuration settings such as DNS servers, timeout, and retries.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     */
    public DnsClient(DcvContext dcvContext) {
        this.dnsServers = dcvContext.getDcvConfiguration().getDnsServers();
        this.dnsTimeout = dcvContext.getDcvConfiguration().getDnsTimeout();
        this.dnsRetries = dcvContext.getDcvConfiguration().getDnsRetries();
        this.logLevelForErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();

        if (this.dnsServers.isEmpty()) {
            log.error("event_id={} message={}", LogEvents.DNS_SERVERS_NOT_CONFIGURED, "Unless the DNS servers are configured, the DNS client will throw IllegalArgumentException.");
        }
    }

    /**
     * Retrieves DNS records of the specified type for the given domains.
     * <p>
     * This method iterates over the configured DNS servers, requesting DNS records of the specified type for each
     * domain in the list. When a valid non-empty response is received, the method returns the DNS data for that domain.
     * Querying is done sequentially and will end as soon as a valid response is received, so it is recommended to
     * carefully consider the order of DNS servers in your configuration. If no valid response is received, it aggregates the errors
     * encountered during the query process and returns an empty result with the collected errors.
     *
     * @param domains The list of domains to query.
     * @param type    The type of DNS record to query.
     * @return The DNS data containing the first records found and any errors encountered.
     */
    public DnsData getDnsData(List<String> domains, DnsType type) {
        verifyInputData(domains);
        Set<DcvError> errors = new HashSet<>();
        List<String> visitedServers = new ArrayList<>();
        for (String server : dnsServers) {
            visitedServers.add(server);
            for (String domain : domains) {
                DnsData dnsData = getDnsData(server, domain, type);
                errors.addAll(dnsData.errors());
                if (!dnsData.records().isEmpty()) {
                    return dnsData;
                }
            }
        }
        return new DnsData(visitedServers, domains.getFirst(), type, List.of(), errors, "");
    }

    /**
     * Verifies the input data for the DNS query.
     * <p>
     * This method checks that the list of domains is not empty and that the DNS servers are configured.
     * If the input data is invalid or missing, the method throws an {@link IllegalArgumentException}
     *
     * @param domains The list of domains to query.
     */
    private void verifyInputData(List<String> domains) {
        if(domains.isEmpty()) {
            throw new IllegalArgumentException("Query domains are not provided.");
        }
        if(this.dnsServers.isEmpty()) {
            throw new IllegalArgumentException("DNS servers are not configured.");
        }
    }

    /**
     * Retrieves DNS data for a specific server, domain, and DNS record type.
     * <p>
     * This method performs a DNS query for the specified server, domain, and DNS record type. It creates a resolver
     * for the DNS server and a lookup for the domain and record type. The method handles common exceptions such as
     * {@link UnknownHostException} and {@link TextParseException}, logging the errors and returning an empty result
     * with the appropriate error codes.
     * The provided server may include a port number separated by a colon. (e.g. 8.8.8.8:53). If no port is provided,
     * the default DNS port (53) is used.
     *
     * @param server The DNS server to query.
     * @param domain The domain to query.
     * @param type   The type of DNS record to query.
     * @return The DNS data containing the records and any errors encountered.
     */
    private DnsData getDnsData(String server, String domain, DnsType type) {
        try {
            int dnsPort = 53;
            String[] serverParts = server.split(":");
            String dnsHostName = serverParts[0];
            if (serverParts.length > 1) {
                dnsPort = Integer.parseInt(serverParts[1]);
            }
            ExtendedResolver resolver = createResolver(dnsHostName, dnsPort);
            resolver.setTimeout(Duration.ofMillis(dnsTimeout));
            resolver.setRetries(dnsRetries);
            Lookup domainLookup = createLookup(domain, mapToDnsIntType(type));
            domainLookup.setResolver(resolver);

            Record[] records = domainLookup.run();
            List<Record> recordList = records != null ? List.of(records) : List.of();
            Set<DcvError> errors = recordList.isEmpty() ? Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND) : Set.of();

            log.info("event_id={} domain={} server={} type={} records={}", LogEvents.DNS_LOOKUP_SUCCESS, domain, server, type, recordList.size());
            return new DnsData(List.of(server), domain, type, recordList, errors, server);
        } catch (UnknownHostException | TextParseException e) {
            DcvError dcvError;
            if (e instanceof UnknownHostException) {
                dcvError = DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
            } else {
                dcvError = DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
            }
            log.atLevel(logLevelForErrors).log("event_id={} domain={} server={} dcv_error={}",
                    LogEvents.DNS_LOOKUP_ERROR, domain, server, dcvError, e);
            return new DnsData(List.of(server), domain, type, List.of(), Set.of(dcvError), server);
        }
    }

    /**
     * Creates a new SimpleResolver for the specified DNS server.
     * <p>
     * This method creates and configures a {@link SimpleResolver} for the specified DNS server and port. If a port is
     * provided, it creates a resolver using the specified port; otherwise, it uses the default DNS port (53). The
     * resolver is then wrapped in an {@link ExtendedResolver} to provide additional functionality such as retries and
     * timeout management.
     *
     * @param server The DNS server to create a resolver for.
     * @param port   The port to use for the resolver. If not port is specified, the default port (53) is used.
     * @return The created ExtendedResolver.
     * @throws UnknownHostException If the DNS server is unknown.
     */
    protected ExtendedResolver createResolver(String server, Integer port) throws UnknownHostException {
        if (port != null) {
            InetSocketAddress address = new InetSocketAddress(server, port);
            return new ExtendedResolver(List.of(new SimpleResolver(address)));
        }
        return new ExtendedResolver(List.of(new SimpleResolver(server)));
    }

    /**
     * Creates a new Lookup for the specified domain and DNS record type.
     * <p>
     * This method creates and configures a {@link Lookup} for the specified domain and DNS record type. The lookup is
     * used to perform the actual DNS query, translating the domain name and record type into a DNS request. The method
     * throws {@link TextParseException} if it is unable to parse the response.
     *
     * @param domain The domain to create a lookup for.
     * @param type   The DNS record type to query.
     * @return The created Lookup.
     * @throws TextParseException If the domain name is invalid.
     */
    protected Lookup createLookup(String domain, int type) throws TextParseException {
        return new Lookup(domain, type);
    }

    /**
     * Maps the DnsType enum to the corresponding integer value used by the DNS library.
     * <p>
     * This method translates the {@link DnsType} enum values into the integer constants used by the DNS library. This
     * mapping is necessary because the DNS library uses integer values to represent different DNS record types, while
     * the client code uses the more readable {@link DnsType} enum.
     *
     * @param dnsRecordType The DnsType to map.
     * @return The corresponding integer value for the DNS record type.
     */
    private int mapToDnsIntType(DnsType dnsRecordType) {
        return switch (dnsRecordType) {
            case CNAME   -> Type.CNAME;
            case TXT     -> Type.TXT;
            case CAA     -> Type.CAA;
            case A       -> Type.A;
            case MX      -> Type.MX;
            case DS      -> Type.DS;
            case RRSIG   -> Type.RRSIG;
        };
    }
}