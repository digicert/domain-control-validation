package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

/**
 * Represents the response from a secondary DNS validation method in the context of MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the agent ID, agent status, DNSSEC validation details,
 * whether the response corroborates with the primary DNS response,
 * the list of DNS records retrieved, the CNAME chain if present, and whether the CNAME chain corroborates.
 *
 * @param agentId                 the identifier of the secondary MPIC agent
 * @param agentStatus             the status reported by the agent for this DNS request
 * @param agentRIR                the Regional Internet Registry associated with the agent
 * @param dnssecDetails           the DNSSEC validation details, or {@code null} if not checked
 * @param corroborates            {@code true} if this secondary response corroborates the primary response
 * @param dnsRecords              the DNS records retrieved by the secondary agent
 * @param cnameChain              the chain of CNAME records encountered during DNS resolution, if any
 * @param cnameChainCorroborates  {@code true} if the CNAME chain corroborates the primary agent's CNAME chain
 */
public record SecondaryDnsResponse(String agentId,
                                   AgentStatus agentStatus,
                                   String agentRIR,
                                   DnssecDetails dnssecDetails,
                                   boolean corroborates,
                                   List<DnsRecord> dnsRecords,
                                   List<DnsRecord> cnameChain,
                                   boolean cnameChainCorroborates) {

    /**
     * Backward-compatible constructor that defaults agentRIR to "UNKNOWN".
     *
     * @param agentId                the identifier of the secondary MPIC agent
     * @param agentStatus            the status reported by the agent for this DNS request
     * @param dnssecDetails          the DNSSEC validation details, or {@code null} if not checked
     * @param corroborates           {@code true} if this secondary response corroborates the primary response
     * @param dnsRecords             the DNS records retrieved by the secondary agent
     * @param cnameChain             the chain of CNAME records encountered during DNS resolution, if any
     * @param cnameChainCorroborates {@code true} if the CNAME chain corroborates the primary agent's CNAME chain
     */
    public SecondaryDnsResponse(String agentId,
                         AgentStatus agentStatus,
                         DnssecDetails dnssecDetails,
                         boolean corroborates,
                         List<DnsRecord> dnsRecords,
                         List<DnsRecord> cnameChain,
                         boolean cnameChainCorroborates){
        this(agentId,agentStatus,"UNKNOWN",dnssecDetails,corroborates,dnsRecords,cnameChain,cnameChainCorroborates);
    }

    /**
     * Backward-compatible constructor that defaults dnssecDetails to null.
     *
     * @param agentId                the identifier of the secondary MPIC agent
     * @param agentStatus            the status reported by the agent for this DNS request
     * @param corroborates           {@code true} if this secondary response corroborates the primary response
     * @param dnsRecords             the DNS records retrieved by the secondary agent
     * @param cnameChain             the chain of CNAME records encountered during DNS resolution, if any
     * @param cnameChainCorroborates {@code true} if the CNAME chain corroborates the primary agent's CNAME chain
     */
    public SecondaryDnsResponse(String agentId,
                                AgentStatus agentStatus,
                                boolean corroborates,
                                List<DnsRecord> dnsRecords,
                                List<DnsRecord> cnameChain,
                                boolean cnameChainCorroborates) {
        this(agentId, agentStatus, null, corroborates, dnsRecords, cnameChain, cnameChainCorroborates);
    }
}
