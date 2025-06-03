package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

public record SecondaryDnsResponse(String agentId,
                                   AgentStatus agentStatus,
                                   boolean corroborates,
                                   List<DnsRecord> dnsRecords) {}
