package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.digicert.validation.mpic.api.AgentStatus.DNS_LOOKUP_SUCCESS;

@Slf4j
public class MpicDnsService {

    private MpicClientInterface mpicClient;

    /**
     * Constructs a new MpicService with the specified configuration.
     *
     * @param dcvContext context where we can find the necessary dependencies / configuration
     */
    public MpicDnsService(DcvContext dcvContext) {
        this.mpicClient = dcvContext.get(MpicClientInterface.class);
    }

    /**
     * Retrieves MPIC DNS details for a list of domains.
     * It will return the first valid and corroborated MPIC response or the first MPIC response with an error.
     *
     * @param domain  Domain name to validate
     * @param dnsType The type of DNS records to retrieve (e.g., TXT, CNAME)
     * @return List of MpicDnsDetails containing the MPIC details, domain, DNS records, and any errors encountered
     */
    public MpicDnsDetails getDnsDetails(String domain, DnsType dnsType) {
        return getDnsDetails(domain, dnsType, null);
    }

    /**
     * Retrieves MPIC DNS details for a given domain, DNS type, and value to check.
     *
     * @param domain        Domain name to validate
     * @param dnsType       DNS record type to query (e.g., TXT, CNAME)
     * @param valueToCheck  Specific value to look for in the DNS records (can be null if not applicable)
     * @return MpicDnsDetails containing the MPIC details, domain, DNS records, and any errors encountered
     */
    public MpicDnsDetails getDnsDetails(String domain, DnsType dnsType, String valueToCheck) {
        MpicDnsResponse mpicDnsResponse = mpicClient.getMpicDnsResponse(domain, dnsType, valueToCheck);
        return mapToMpicDnsDetailsWithErrorCheck(mpicDnsResponse, domain);
    }

    /**
     * Retrieves only the primary DNS response for a given domain and DNS type.
     *
     * @param domain  Domain name to validate
     * @param dnsType DNS record type to query (e.g., TXT, CNAME)
     * @return PrimaryDnsResponse containing details from the primary DNS agent
     */
    public PrimaryDnsResponse getPrimaryDnsDetails(String domain, DnsType dnsType) {
        return mpicClient.getPrimaryOnlyDnsResponse(domain, dnsType);
    }

    private MpicDnsDetails mapToMpicDnsDetailsWithErrorCheck(MpicDnsResponse mpicDnsResponse, String domain) {
        if (mpicDnsResponse == null ||
                mpicDnsResponse.primaryDnsResponse() == null ||
                mpicDnsResponse.mpicStatus() == MpicStatus.ERROR) {
            MpicDetails mpicDetails = new MpicDetails(false,
                    null,
                    0,
                    0,
                    Collections.emptyMap(),
                    null);
            log.info("event_id={} mpic_dns_response={}", LogEvents.MPIC_INVALID_RESPONSE, mpicDnsResponse);
            return new MpicDnsDetails(mpicDetails,
                    domain,
                    List.of(),
                    DcvError.MPIC_INVALID_RESPONSE);
        }

        DcvError dcvError = mapToDcvErrorOrNull(mpicDnsResponse.primaryDnsResponse(), mpicDnsResponse.mpicStatus());
        log.info("event_id={} agent_status={} domain={} dns_type={} mpic_status={} dcv_error={}",
                LogEvents.DNS_LOOKUP_STATUS,
                mpicDnsResponse.primaryDnsResponse().agentStatus(),
                domain,
                mpicDnsResponse.primaryDnsResponse().requestedType(),
                mpicDnsResponse.mpicStatus(),
                dcvError);
        return mapToMpicDnsDetails(mpicDnsResponse, domain, dcvError);
    }

    public DcvError mapToDcvErrorOrNull(PrimaryDnsResponse primaryDnsResponse, MpicStatus mpicStatus) {
        DcvError dcvError = null;
        if (primaryDnsResponse == null) {
            return DcvError.MPIC_INVALID_RESPONSE;
        }

        if (primaryDnsResponse.agentStatus() != DNS_LOOKUP_SUCCESS) {
            dcvError = switch (primaryDnsResponse.agentStatus()) {
                case DNS_LOOKUP_BAD_REQUEST -> DcvError.DNS_LOOKUP_BAD_REQUEST;
                case DNS_LOOKUP_TIMEOUT -> DcvError.DNS_LOOKUP_TIMEOUT;
                case DNS_LOOKUP_IO_EXCEPTION -> DcvError.DNS_LOOKUP_IO_EXCEPTION;
                case DNS_LOOKUP_DOMAIN_NOT_FOUND -> DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND;
                case DNS_LOOKUP_RECORD_NOT_FOUND -> DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
                case DNS_LOOKUP_TEXT_PARSE_EXCEPTION -> DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
                case DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION -> DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
                default -> DcvError.MPIC_INVALID_RESPONSE;
            };
        }
        else if (primaryDnsResponse.dnsRecords() == null ||
                primaryDnsResponse.dnsRecords().isEmpty()) {
            dcvError = DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
        }
        else if (mpicStatus == MpicStatus.VALUE_NOT_FOUND || mpicStatus == MpicStatus.PRIMARY_AGENT_FAILURE) {
            dcvError = DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
        }
        else if (mpicClient.shouldEnforceCorroboration() && mpicStatus == MpicStatus.NON_CORROBORATED) {
            dcvError = DcvError.MPIC_CORROBORATION_ERROR;
        }

        return dcvError;
    }

    private MpicDnsDetails mapToMpicDnsDetails(MpicDnsResponse mpicDnsResponse, String domain, DcvError dcvError) {
        boolean corroborated = MpicStatus.CORROBORATED.equals(mpicDnsResponse.mpicStatus());
        String primaryAgentId = mpicDnsResponse.primaryDnsResponse().agentId();
        int numSecondariesChecked = mpicDnsResponse.secondaryDnsResponses().size();
        long numCorroborated = mpicDnsResponse.secondaryDnsResponses().stream()
                .filter(SecondaryDnsResponse::corroborates)
                .count();
        Map<String, Boolean> agentIdToCorroboration = mpicDnsResponse.secondaryDnsResponses().stream()
                .collect(HashMap::new,
                        (map, response) -> map.put(response.agentId(), response.corroborates()),
                        HashMap::putAll);

        MpicDetails mpicDetails = new MpicDetails(corroborated,
                primaryAgentId,
                numSecondariesChecked,
                numCorroborated,
                agentIdToCorroboration,
                extractCnameChain(mpicDnsResponse.primaryDnsResponse().cnameChain()));

        return new MpicDnsDetails(mpicDetails,
                domain,
                mpicDnsResponse.primaryDnsResponse().dnsRecords(),
                dcvError);
    }

    private List<String> extractCnameChain(List<DnsRecord> cnameChain) {
        if (cnameChain == null) {
            return null;
        }

        return cnameChain.stream()
                .map(record -> {
                    String source = record.name();
                    String target = record.value();

                    if (source != null && source.endsWith(".")) {
                        source = source.substring(0, source.length() - 1);
                    }
                    if (target != null && target.endsWith(".")) {
                        target = target.substring(0, target.length() - 1);
                    }
                    return source + " -> " + target;
                })
                .distinct()
                .toList();
    }
}
