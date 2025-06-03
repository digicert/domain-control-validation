package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.AgentStatus;

import java.util.List;

public record PrimaryDnsResponse (String agentId,
                                  AgentStatus agentStatus,
                                  List<DnsRecord> dnsRecords,
                                  DnsType requestedType,
                                  String requestedDomain) {}
