package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

/**
 * Represents the response from a primary DNS validation method in the context of MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the agent ID, agent status, DNSSEC validation details, DNS records retrieved,
 * the type of DNS record requested, the domain for which the DNS validation was performed,
 * and the CNAME chain if present.
 */
public record PrimaryDnsResponse (String agentId,
                                  AgentStatus agentStatus,
                                  DnssecDetails dnssecDetails,
                                  List<DnsRecord> dnsRecords,
                                  DnsType requestedType,
                                  String requestedDomain,
                                  List<DnsRecord> cnameChain) {

    /** Backward-compatible constructor that defaults dnssecDetails to null. */
    public PrimaryDnsResponse(String agentId,
                              AgentStatus agentStatus,
                              List<DnsRecord> dnsRecords,
                              DnsType requestedType,
                              String requestedDomain,
                              List<DnsRecord> cnameChain) {
        this(agentId, agentStatus, null, dnsRecords, requestedType, requestedDomain, cnameChain);
    }
}
