package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

/**
 * Represents the response from a DNS validation method for MPIC (Multi-Perspective Corroboration).
 * This record encapsulates the primary DNS response, a list of secondary DNS responses,
 * the overall MPIC status, the number of agent corroborations, any error message encountered,
 * and the DNSSEC validation details.
 *
 * @param primaryDnsResponse      the response from the primary MPIC agent
 * @param secondaryDnsResponses   the responses from secondary MPIC agents
 * @param mpicStatus              the overall MPIC corroboration status
 * @param numAgentCorroborations  the number of agents that corroborated the primary response
 * @param errorMessage            an error message if the MPIC request failed, or {@code null} if none
 * @param dnssecDetails           the DNSSEC validation details, or {@code null} if not checked
 */
public record MpicDnsResponse(PrimaryDnsResponse primaryDnsResponse,
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
