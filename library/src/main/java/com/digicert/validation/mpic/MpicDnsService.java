package com.digicert.validation.mpic;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

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
     * @param domain  List of domain names to validate
     * @param dnsType The type of DNS records to retrieve (e.g., TXT, CNAME)
     * @return List of MpicDnsDetails containing the MPIC details, domain, DNS records, and any errors encountered
     */
    public MpicDnsDetails getDnsDetails(String domain, DnsType dnsType) {
        MpicDnsResponse mpicDnsResponse = mpicClient.getMpicDnsResponse(domain, dnsType);
        return mapToMpicDnsDetailsWithErrorCheck(mpicDnsResponse, domain);
    }

    private MpicDnsDetails mapToMpicDnsDetailsWithErrorCheck(MpicDnsResponse mpicDnsResponse, String domain) {
        if (mpicDnsResponse == null ||
                mpicDnsResponse.primaryDnsResponse() == null ||
                mpicDnsResponse.mpicStatus() == MpicStatus.ERROR) {
            MpicDetails mpicDetails = new MpicDetails(false,
                    null,
                    0,
                    0,
                    Collections.emptyMap());
            log.info("event_id={} mpic_file_response={}", LogEvents.MPIC_INVALID_RESPONSE, mpicDnsResponse);
            return new MpicDnsDetails(mpicDetails,
                    domain,
                    List.of(),
                    DcvError.MPIC_INVALID_RESPONSE);
        }

        if (mpicDnsResponse.primaryDnsResponse().agentStatus() != DNS_LOOKUP_SUCCESS) {
            DcvError dcvError = switch (mpicDnsResponse.primaryDnsResponse().agentStatus()) {
                case DNS_LOOKUP_BAD_REQUEST -> DcvError.DNS_LOOKUP_BAD_REQUEST;
                case DNS_LOOKUP_TIMEOUT -> DcvError.DNS_LOOKUP_TIMEOUT;
                case DNS_LOOKUP_IO_EXCEPTION -> DcvError.DNS_LOOKUP_IO_EXCEPTION;
                case DNS_LOOKUP_DOMAIN_NOT_FOUND -> DcvError.DNS_LOOKUP_DOMAIN_NOT_FOUND;
                case DNS_LOOKUP_RECORD_NOT_FOUND -> DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
                case DNS_LOOKUP_TEXT_PARSE_EXCEPTION -> DcvError.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
                case DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION -> DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
                default -> DcvError.MPIC_INVALID_RESPONSE;
            };
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.DNS_LOOKUP_ERROR, mpicDnsResponse.primaryDnsResponse().agentStatus(), dcvError);
            return mapToMpicDnsDetails(mpicDnsResponse, domain, dcvError);
        }

        if (mpicDnsResponse.primaryDnsResponse().dnsRecords() == null ||
                mpicDnsResponse.primaryDnsResponse().dnsRecords().isEmpty()) {
            DcvError dcvError = DcvError.DNS_LOOKUP_RECORD_NOT_FOUND;
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.DNS_LOOKUP_ERROR, mpicDnsResponse.primaryDnsResponse().agentStatus(), dcvError);
            return mapToMpicDnsDetails(mpicDnsResponse, domain, dcvError);
        }

        if (mpicClient.shouldEnforceCorroboration() && mpicDnsResponse.mpicStatus() == MpicStatus.NON_CORROBORATED) {
            DcvError dcvError = DcvError.MPIC_CORROBORATION_ERROR;
            log.info("event_id={} agent_status={} dcv_error={}",
                    LogEvents.DNS_LOOKUP_ERROR, mpicDnsResponse.primaryDnsResponse().agentStatus(), dcvError);
            return mapToMpicDnsDetails(mpicDnsResponse, domain, DcvError.MPIC_CORROBORATION_ERROR);
        }

        log.info("event_id={} agent_status={} domain={}",
                LogEvents.DNS_LOOKUP_SUCCESS, mpicDnsResponse.primaryDnsResponse().agentStatus(), domain);
        return mapToMpicDnsDetails(mpicDnsResponse, domain, null);
    }

    private MpicDnsDetails mapToMpicDnsDetails(MpicDnsResponse mpicDnsResponse, String domain, DcvError dcvError) {
        boolean corroborated = MpicStatus.CORROBORATED.equals(mpicDnsResponse.mpicStatus());
        String primaryAgentId = mpicDnsResponse.primaryDnsResponse().agentId();
        int serversChecked = mpicDnsResponse.secondaryDnsResponses().size();
        long numCorroborated = mpicDnsResponse.secondaryDnsResponses().stream()
                .filter(SecondaryDnsResponse::corroborates)
                .count();
        Map<String, Boolean> agentIdToCorroboration = mpicDnsResponse.secondaryDnsResponses().stream()
                .collect(HashMap::new,
                        (map, response) -> map.put(response.agentId(), response.corroborates()),
                        HashMap::putAll);

        MpicDetails mpicDetails = new MpicDetails(corroborated,
                primaryAgentId,
                serversChecked,
                numCorroborated,
                agentIdToCorroboration);

        return new MpicDnsDetails(mpicDetails,
                domain,
                mpicDnsResponse.primaryDnsResponse().dnsRecords(),
                dcvError);
    }
}
