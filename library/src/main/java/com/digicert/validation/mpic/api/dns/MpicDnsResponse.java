package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

/**
 * Represents the response from a DNS validation method for MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the primary DNS response, a list of secondary DNS responses,
 * the overall MPIC status, the number of agent corroborations, any error message encountered,
 * and the DNSSEC validation details.
 */
public record MpicDnsResponse (PrimaryDnsResponse primaryDnsResponse,
                               List<SecondaryDnsResponse> secondaryDnsResponses,
                               MpicStatus mpicStatus,
                               long numAgentCorroborations,
                               String errorMessage,
                               DnssecDetails dnssecDetails) {

    /** Backward-compatible constructor that defaults dnssecDetails to null. */
    public MpicDnsResponse(PrimaryDnsResponse primaryDnsResponse,
                           List<SecondaryDnsResponse> secondaryDnsResponses,
                           MpicStatus mpicStatus,
                           long numAgentCorroborations,
                           String errorMessage) {
        this(primaryDnsResponse, secondaryDnsResponses, mpicStatus, numAgentCorroborations, errorMessage, null);
    }
}
