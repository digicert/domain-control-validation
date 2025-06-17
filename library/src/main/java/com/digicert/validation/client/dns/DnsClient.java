package com.digicert.validation.client.dns;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.client.ClientStatus;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

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
                if (!dnsData.values().isEmpty()) {
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
            String[] serverParts = server.split(":");
            String dnsHostName = serverParts[0];
            int dnsPort = serverParts.length > 1 ? Integer.parseInt(serverParts[1]) : 53;

            ExtendedResolver resolver = createResolver(dnsHostName, dnsPort);
            resolver.setTimeout(Duration.ofMillis(dnsTimeout));
            resolver.setRetries(dnsRetries);

            Record query = Record.newRecord(Name.fromString(createZoneFromDomain(domain)), mapToDnsIntType(type), DClass.IN);
            Message response = resolver.send(Message.newQuery(query));

            List<DnsValue> values = getDnsValues(response);
            ClientStatus clientStatus = getClientStatus(response, values);

            Set<DcvError> errors = new HashSet<>();
            if(clientStatus != ClientStatus.DNS_LOOKUP_SUCCESS){
                errors.add(mapClientStatusToDcvError(clientStatus));
            }

            return new DnsData(List.of(server), domain, type, values, errors, server);
        } catch (Exception e) {
            return handleDnsException(e, type, domain, server);
        }
    }

    /**
     * Creates a zone name from the provided domain.
     * <p>
     * This method ensures that the domain ends with a dot (.) to conform to DNS zone naming conventions. If the domain
     * does not end with a dot, it appends one.
     *
     * @param domain The domain to convert into a zone name.
     * @return The zone name created from the domain.
     */
    private String createZoneFromDomain(String domain) {
        if (!domain.endsWith(".")) {
            return domain + ".";
        }
        return domain;
    }

    /**
     * Extracts DNS values from the response message.
     * <p>
     * This method retrieves the DNS records from the answer section of the response message and maps them to a list of
     * {@link DnsValue} objects. If the response code is NOERROR, it processes the records; otherwise, it returns an
     * empty list.
     *
     * @param response The DNS response message.
     * @return A list of DnsValue objects containing the DNS records found in the response.
     */
    private List<DnsValue> getDnsValues(Message response) {
        List<DnsValue> values = List.of();
        if (response.getRcode() == Rcode.NOERROR) {
            values = response.getSection(Section.ANSWER).stream()
                    .map(this::mapRecordToDnsValue)
                    .toList();
        }
        return values;
    }

    /**
     * Maps a DNS record to a DnsValue object.
     * <p>
     * This method converts a DNS record into a DnsValue object, extracting relevant information such as the value,
     * name, type, and TTL. It handles different types of DNS records, including TXT, CNAME, A, MX, CAA, DS, and RRSIG.
     *
     * @param recordValue The DNS record to map.
     * @return A DnsValue object containing the mapped data.
     */
    private DnsValue mapRecordToDnsValue(Record recordValue) {
        DnsValue dnsValue = new DnsValue();
        switch (recordValue) {
            case TXTRecord txtRecord -> dnsValue.setValue(txtRecord.rdataToString());
            case CNAMERecord cnameRecord -> dnsValue.setValue(cnameRecord.getTarget().toString());
            case ARecord aRecord -> dnsValue.setValue(aRecord.getAddress().getHostAddress());
            case MXRecord mxRecord -> dnsValue.setValue(mxRecord.getTarget().toString());
            case CAARecord caaRecord -> dnsValue = populateCaaRecordData(caaRecord);
            case DSRecord dsRecord -> dnsValue.setValue(dsRecord.toString());
            case RRSIGRecord rrsigRecord -> dnsValue.setValue(rrsigRecord.toString());
            default -> throw new IllegalStateException("Unexpected value: " + recordValue);
        }
        dnsValue.setName(recordValue.getName().toString());
        dnsValue.setDnsType(DnsType.fromInt(recordValue.getType()));
        dnsValue.setTtl(recordValue.getTTL());
        return dnsValue;
    }

    /**
     * Populates the CAARecord data into a DnsValue object.
     * <p>
     * This method extracts the flags, tag, and value from the CAARecord and sets them in a new CaaRecord object.
     *
     * @param recordValue The CAARecord to populate data from.
     * @return A CaaRecord object containing the populated data.
     */
    private CaaValue populateCaaRecordData(CAARecord recordValue) {
        CaaValue caaValue = new CaaValue();
        caaValue.setFlag(recordValue.getFlags());
        caaValue.setTag(recordValue.getTag());
        caaValue.setValue(recordValue.getValue());
        return caaValue;
    }

    /**
     * Handles exceptions that occur during DNS queries.
     * <p>
     * This method processes exceptions thrown during DNS queries, logging the error and returning a DnsData object
     * with the appropriate error codes. It categorizes the exceptions into specific client statuses and maps them to
     * corresponding {@link DcvError} values.
     *
     * @param e      The exception that occurred during the DNS query.
     * @param type   The type of DNS record that was being queried.
     * @param domain The domain that was being queried.
     * @param server The DNS server that was being queried.
     * @return A DnsData object containing the error information.
     */
    private DnsData handleDnsException(@NonNull Exception e, DnsType type, String domain, String server) {
        ClientStatus clientStatus = switch (e) {
            case TextParseException ignored -> ClientStatus.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
            case UnknownHostException ignored -> ClientStatus.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
            case IOException ex -> {
                if (ex.getCause() instanceof TimeoutException) {
                    yield ClientStatus.DNS_LOOKUP_TIMEOUT;
                } else {
                    yield ClientStatus.DNS_LOOKUP_IO_EXCEPTION;
                }
            }
            default -> ClientStatus.INTERNAL_SERVER_ERROR;
        };
        if(clientStatus == ClientStatus.INTERNAL_SERVER_ERROR) {
            log.info("event_id={} domain={} dns_type={} server={} agent_status={}", LogEvents.DNS_LOOKUP_ERROR, domain, type, server, clientStatus, e);
        } else {
            log.info("event_id={} domain={} dns_type={} server={} agent_status={}", LogEvents.DNS_LOOKUP_ERROR, domain, type, server, clientStatus);
        }

        return new DnsData(List.of(server), domain, type, List.of(), Set.of(mapClientStatusToDcvError(clientStatus)), server);
    }

    /**
     * Determines the client status based on the DNS response message and the found DNS values.
     * <p>
     * This method analyzes the response code of the DNS message and the list of found DNS values to determine the
     * appropriate client status. It handles different response codes such as NOERROR, NXDOMAIN, and others, and
     * categorizes the status accordingly.
     *
     * @param message         The DNS response message.
     * @param foundDnsValues  The list of DNS values found in the response.
     * @return The determined client status based on the response code and found values.
     */
    private ClientStatus getClientStatus(Message message, List<DnsValue> foundDnsValues) {
        int rcode = message.getRcode();
        ClientStatus clientStatus;

        switch (rcode) {
            case Rcode.NOERROR ->
                // If the response code is NOERROR, check if are DNS values that we found
                    clientStatus = foundDnsValues.isEmpty() ? ClientStatus.DNS_LOOKUP_RECORD_NOT_FOUND : ClientStatus.DNS_LOOKUP_SUCCESS;

            case Rcode.NXDOMAIN -> {
                // This response could mean that the domain does not exist or the record does not exist
                // Check if the answer section is empty to determine the status
                if (message.getSection(Section.ANSWER).isEmpty()) {
                    // If the response code is NXDOMAIN and there are no values, treat it as domain not found
                    clientStatus = ClientStatus.DNS_LOOKUP_DOMAIN_NOT_FOUND;
                } else {
                    // If the response code is NXDOMAIN but there are values, treat it as a record not found
                    clientStatus = ClientStatus.DNS_LOOKUP_RECORD_NOT_FOUND;
                }
            }
            default ->
                // Treat REFUSED and all other cases as IO Exception
                    clientStatus = ClientStatus.DNS_LOOKUP_IO_EXCEPTION;
        }

        return clientStatus;
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
        InetSocketAddress address = new InetSocketAddress(server, port);
        return new ExtendedResolver(List.of(new SimpleResolver(address)));
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

    /**
     * Maps the {@link ClientStatus} enum to the corresponding {@link DcvError} DcvError.
     * <p>
     * throws an {@link IllegalArgumentException} if the provided ClientStatus is not recognized.
     * @param clientStatus The ClientStatus to map.
     * @return The corresponding DcvError for the given ClientStatus.
     */
    DcvError mapClientStatusToDcvError(ClientStatus clientStatus) {
        return switch (clientStatus) {
            case DNS_LOOKUP_BAD_REQUEST -> DcvError.DNS_LOOKUP_BAD_REQUEST;
            case DNS_LOOKUP_TEXT_PARSE_EXCEPTION -> DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
            case DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION -> DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
            case DNS_LOOKUP_TIMEOUT -> DcvError.DNS_LOOKUP_TIMEOUT;
            case DNS_LOOKUP_IO_EXCEPTION -> DcvError.DNS_LOOKUP_IO_EXCEPTION;
            case DNS_LOOKUP_DOMAIN_NOT_FOUND -> DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND;
            case DNS_LOOKUP_RECORD_NOT_FOUND -> DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
            case INTERNAL_SERVER_ERROR -> DcvError.DNS_LOOKUP_EXCEPTION;
            default -> throw new IllegalArgumentException("Unknown ClientStatus: " + clientStatus);
        };
    }
}
