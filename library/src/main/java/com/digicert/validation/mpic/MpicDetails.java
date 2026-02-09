package com.digicert.validation.mpic;

import com.digicert.validation.mpic.api.dns.DnssecDetails;

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
 */
public record MpicDetails(boolean corroborated,
                          String primaryAgentId,
                          long secondaryServersChecked,
                          long secondaryServersCorroborated,
                          DnssecDetails dnssecDetails,
                          Map<String, Boolean> agentIdToCorroboration,
                          List<String> cnameChain) {

    /** Backward-compatible constructor that defaults dnssecDetails to {@link DnssecDetails#notChecked()}. */
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
