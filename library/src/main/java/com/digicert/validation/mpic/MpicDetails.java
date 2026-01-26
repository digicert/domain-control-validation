package com.digicert.validation.mpic;

import java.util.List;
import java.util.Map;

/**
 * Represents the summary of an MPIC (Multi-Perspective Corroboration) response.
 * This record encapsulates whether the MPIC was corroborated,
 * the primary agent ID,
 * the number of servers checked,
 * the number of servers corroborated,
 * a map of agent IDs to their corroboration status,
 * and the CNAME chain if present.
 */
public record MpicDetails(boolean corroborated,
                          String primaryAgentId,
                          long secondaryServersChecked,
                          long secondaryServersCorroborated,
                          Map<String, Boolean> agentIdToCorroboration,
                          List<String> cnameChain) {
}
