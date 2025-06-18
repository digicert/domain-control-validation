package com.digicert.validation.client;

import com.digicert.validation.methods.email.prepare.provider.DnsCaaEmailProvider;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.List;

@Service
public class PdnsClient {
    private final RestTemplate restTemplate;

    private static final String PDNS_BASE_URL = "http://localhost:8081/api/v1/servers/localhost/zones";

    public PdnsClient() {
        this.restTemplate = new RestTemplateBuilder()
                // This value taken from the API Key provided in the docker-compose file to the PowerDNS server
                .defaultHeader("X-API-Key", "secret")
                .build();
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        restTemplate.setErrorHandler(new Ignore404StatusResponseErrorHandler());
    }

    public void createLocalhostARecord(String domain) {
        // Configured to match the PowerDNS server running in the docker-compose file
        addRandomValueToRecord(domain, List.of("127.0.0.1"), PdnsRecordType.A, "");
    }

    public void addRandomValueToRecord(String domain, String randomValue, PdnsRecordType pdnsRecordType) {
        addRandomValueToRecord(domain, List.of(randomValue), pdnsRecordType, "_dnsAuth");
    }

    public void addRandomValueToRecord(String domain, List<String> randomValues, PdnsRecordType pdnsRecordType, String recordNamePrefix) {
        String domainId = domain + ".";

        ResponseEntity<String> zoneRecord = restTemplate.exchange(PDNS_BASE_URL + "/{domainId}", HttpMethod.GET, null, String.class, domainId);
        if (zoneRecord.getStatusCode().is4xxClientError()) {
            // If the zone does not exist, create it
            PdnsZone pdnsZone = new PdnsZone(domainId, "Native");
            restTemplate.postForObject(PDNS_BASE_URL, pdnsZone, String.class);
        }

        PdnsPatchRequest pndsPatchRequest = createPndsPatchRequest(domainId, randomValues, pdnsRecordType, recordNamePrefix);
        restTemplate.patchForObject(PDNS_BASE_URL + "/{domainId}", pndsPatchRequest, String.class, domainId);
    }

    public void addCaaRecord(String domain, List<String> recordValues) {
        String domainId = domain + ".";
        ResponseEntity<String> zoneRecord = restTemplate.exchange(PDNS_BASE_URL + "/{domainId}", HttpMethod.GET, null, String.class, domainId);
        if (zoneRecord.getStatusCode().is4xxClientError()) {
            // If the zone does not exist, create it
            PdnsZone pdnsZone = new PdnsZone(domainId, "Native");
            restTemplate.postForObject(PDNS_BASE_URL, pdnsZone, String.class);
        }

        PdnsPatchRequest pndsPatchRequest = createPndsPatchRequest(domainId, recordValues, PdnsRecordType.CAA, "");
        restTemplate.patchForObject(PDNS_BASE_URL + "/{domainId}", pndsPatchRequest, String.class, domainId);
    }

    private PdnsPatchRequest createPndsPatchRequest(String domainId,
                                                    List<String> randomValues,
                                                    PdnsRecordType pdnsRecordType,
                                                    String recordNamePrefix) {
        RRSet rrSet = createRRSet(domainId, randomValues, pdnsRecordType, recordNamePrefix);
        return new PdnsPatchRequest(List.of(rrSet));
    }

    private RRSet createRRSet(String domainId,
                              List<String> values,
                              PdnsRecordType pdnsRecordType,
                              String recordNamePrefix) {

        String recordName = getRecordName(domainId, recordNamePrefix);
        String recordType = getRecordType(pdnsRecordType);
        List<DnsRecord> dnsRecords = createDnsRecords(pdnsRecordType, values, domainId);

        return new RRSet(recordName, recordType, 1, "REPLACE", dnsRecords);
    }

    private static String getRecordType(PdnsRecordType pdnsRecordType) {
        return pdnsRecordType.toString();
    }

    private static String getRecordName(String domainId, String recordNamePrefix) {
        if (recordNamePrefix.isEmpty()) {
            return String.format("%s", domainId);
        } else {
            return String.format("%s.%s", recordNamePrefix, domainId);
        }
    }

    private List<DnsRecord> createDnsRecords(PdnsRecordType pdnsRecordType, List<String> values, String domainId) {
        return values.stream()
                .map(value -> createDnsRecord(pdnsRecordType, value, domainId))
                .toList();
    }

    private DnsRecord createDnsRecord(PdnsRecordType pdnsRecordType, String value, String domainId) {
        String content = switch (pdnsRecordType) {
            case TXT -> "\"" + value + "\"";
            case CAA -> String.format("%d %s \"%s\"", 0, DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG, value);
            case CNAME -> String.format("%s.%s", value, domainId);
            case A -> value;
        };
        return new DnsRecord(content, false);
    }

    /**
     * A PowerDNS Zone.
     * <pre>
     * {
     *    "name": "example.com.",
     *    "kind": "Native"
     * }
     * </pre>
     *
     * @param name The name of the zone.
     * @param kind The kind of the zone.
     */
    public record PdnsZone(String name, String kind) { }

    /**
     * A PowerDNS Patch Request.
     * <pre>
     * {
     *    "rrsets": [
     *        {
     *            "name": "test-domain-one.org.",
     *            "type": "TXT",
     *            "ttl": 1,
     *            "changetype": "REPLACE",
     *            "records": [
     *                {
     *                    "content": "\"6px47755jh7h8vw56vc277nw7jlkt7w0\"",
     *                    "disabled": false
     *                }
     *            ]
     *        }
     *    ]
     * }
     * </pre>
     *
     * @param rrsets The list of RRSet objects.
     */
    public record PdnsPatchRequest(List<RRSet> rrsets) { }

    public record RRSet(String name, String type, int ttl, String changetype, List<DnsRecord> records) { }

    public record DnsRecord(String content, boolean disabled) { }

    public enum PdnsRecordType {
        TXT,
        CAA,
        CNAME,
        A,
    }

    static class Ignore404StatusResponseErrorHandler extends DefaultResponseErrorHandler {
        @Override
        public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
            if (response.getStatusCode() != HttpStatus.NOT_FOUND) {
                super.handleError(url, method, response);
            }
        }

        @Override
        public void handleError(ClientHttpResponse response) throws IOException {
            if (response.getStatusCode() != HttpStatus.NOT_FOUND) {
                super.handleError(response);
            }
        }
    }
}
