package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

/**
 * Represents the response from a DNS validation method for MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the primary DNS response, a list of secondary DNS responses,
 * the overall MPIC status, the number of agent corroborations, and any error message encountered.
 */
public record MpicDnsResponse (PrimaryDnsResponse primaryDnsResponse,
                               List<SecondaryDnsResponse> secondaryDnsResponses,
                               MpicStatus mpicStatus,
                               long numAgentCorroborations,
                               String errorMessage) {
}
