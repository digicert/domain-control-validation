package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

/**
 * Represents the response from a secondary DNS validation method in the context of MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the agent ID, agent status, DNSSEC validation details,
 * whether the response corroborates with the primary DNS response,
 * the list of DNS records retrieved, the CNAME chain if present, and whether the CNAME chain corroborates.
 */
public record SecondaryDnsResponse(String agentId,
                                   AgentStatus agentStatus,
                                   DnssecDetails dnssecDetails,
                                   boolean corroborates,
                                   List<DnsRecord> dnsRecords,
                                   List<DnsRecord> cnameChain,
                                   boolean cnameChainCorroborates) {

    /** Backward-compatible constructor that defaults dnssecDetails to null. */
    public SecondaryDnsResponse(String agentId,
                                AgentStatus agentStatus,
                                boolean corroborates,
                                List<DnsRecord> dnsRecords,
                                List<DnsRecord> cnameChain,
                                boolean cnameChainCorroborates) {
        this(agentId, agentStatus, null, corroborates, dnsRecords, cnameChain, cnameChainCorroborates);
    }
}
