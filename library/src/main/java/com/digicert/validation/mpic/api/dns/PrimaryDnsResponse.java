package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

/**
 * Represents the response from a primary DNS validation method in the context of MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the agent ID, agent status, DNS records retrieved, the type of DNS record requested,
 * and the domain for which the DNS validation was performed.
 */
public record PrimaryDnsResponse (String agentId,
                                  AgentStatus agentStatus,
                                  List<DnsRecord> dnsRecords,
                                  DnsType requestedType,
                                  String requestedDomain) {}
