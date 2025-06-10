package com.digicert.validation.mpic;

import java.util.Map;

/**
 * Represents the summary of an MPIC (Multi-Perspective Corroboration) response .
 * This record encapsulates whether the MPIC was corroborated,
 * the primary agent ID,
 * the number of servers checked,
 * the number of servers corroborated,
 * and a map of agent IDs to their corroboration status.
 */
public record MpicDetails(boolean corroborated,
                          String primaryAgentId,
                          long numServersChecked,
                          long numServersCorroborated,
                          Map<String, Boolean> agentIdToCorroboration) {
}
