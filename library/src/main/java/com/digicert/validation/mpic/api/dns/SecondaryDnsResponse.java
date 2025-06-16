package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

/**
 * Represents the response from a secondary DNS validation method in the context of MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the agent ID, agent status, whether the response corroborates with the primary DNS response,
 * and the list of DNS records retrieved.
 */
public record SecondaryDnsResponse(String agentId,
                                   AgentStatus agentStatus,
                                   boolean corroborates,
                                   List<DnsRecord> dnsRecords) {}
