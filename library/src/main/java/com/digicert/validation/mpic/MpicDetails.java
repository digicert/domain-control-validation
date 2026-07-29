package com.digicert.validation.mpic;

import com.digicert.validation.mpic.api.dns.DnssecDetails;
import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Represents the summary of an MPIC (Multi-Perspective Corroboration) response.
 * This record encapsulates whether the MPIC was corroborated,
 * the primary agent ID,
 * the number of servers checked,
 * the number of servers corroborated,
 * the DNSSEC validation details,
 * a map of agent IDs to their corroboration status,
 * and the CNAME chain if present.
 *
 * @param corroborated                  {@code true} if the MPIC corroboration was successful
 * @param primaryAgentId                the identifier of the primary MPIC agent
 * @param secondaryServersChecked       the number of secondary servers that were checked
 * @param secondaryServersCorroborated  the number of secondary servers that corroborated the result
 * @param dnssecDetails                 the DNSSEC validation details for this response
 * @param agentIdToCorroboration        a map from agent ID to whether that agent corroborated
 * @param cnameChain                    the CNAME chain encountered during DNS resolution, if any
 */
@Builder
public record MpicDetails(boolean corroborated,
                          String primaryAgentId,
                          long secondaryServersChecked,
                          long secondaryServersCorroborated,
                          DnssecDetails dnssecDetails,
                          Map<String, Boolean> agentIdToCorroboration,
                          List<String> cnameChain) {

    /**
     * Backward-compatible constructor that defaults dnssecDetails to {@link DnssecDetails#notChecked()}.
     *
     * @param corroborated                  {@code true} if the MPIC corroboration was successful
     * @param primaryAgentId                the identifier of the primary MPIC agent
     * @param secondaryServersChecked       the number of secondary servers that were checked
     * @param secondaryServersCorroborated  the number of secondary servers that corroborated the result
     * @param agentIdToCorroboration        a map from agent ID to whether that agent corroborated
     * @param cnameChain                    the CNAME chain encountered during DNS resolution, if any
     */
    public MpicDetails(boolean corroborated,
                       String primaryAgentId,
                       long secondaryServersChecked,
                       long secondaryServersCorroborated,
                       Map<String, Boolean> agentIdToCorroboration,
                       List<String> cnameChain) {
        this(corroborated, primaryAgentId, secondaryServersChecked, secondaryServersCorroborated,
                DnssecDetails.notChecked(), agentIdToCorroboration, cnameChain);
    }
}
