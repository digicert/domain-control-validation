package com.digicert.validation.utils;

import java.util.Set;

/**
 * Evaluates whether MPIC secondary agent responses meet corroboration thresholds.
 *
 * <p>The thresholds implemented here are used by the DNS persistent-value flow to enforce
 * CA/Browser Forum Baseline Requirements section 3.2.2.9 corroboration expectations based on
 * the number of available secondary agents and regional diversity. See
 * <a href="https://cabforum.org/working-groups/server/baseline-requirements/">CA/Browser Forum
 * Baseline Requirements</a>.</p>
 */

public final class MpicCorroborationEvaluator {

    private MpicCorroborationEvaluator() {
    }

    public static boolean corroborates(long totalSecondaryAgentCount,
                                       long totalCorroboratingAgentCount,
                                       long uniqueCorroboratingRegions){
        long requiredSecondaries = getRequiredSecondaries(totalSecondaryAgentCount);
        int requiredRegions = getRequiredRegions(requiredSecondaries);
        return uniqueCorroboratingRegions >= requiredRegions
                && totalCorroboratingAgentCount >= requiredSecondaries;
    }

    private static int getRequiredRegions(long requiredSecondaries) {
        if (requiredSecondaries == 1) {
            // If only 1 corroboration is required, it can be from any region
            return 1;
        } else {
            // Otherwise, require corroboration from at least 2 different regions
            return 2;
        }
    }

    private static long getRequiredSecondaries(long totalSecondaryAgents) {

        // Ensure the required total secondary agents is at least the minimum required

        // For larger numbers of agents, scale the requirement per CA/Browser Forum guidelines
        long requiredSecondaries;
        if (totalSecondaryAgents <= 5) {
            // For 2-5 agents, require all but one
            requiredSecondaries = totalSecondaryAgents - 1;
        } else {
            requiredSecondaries = totalSecondaryAgents - 2; // For more than 6 agents, require at least 2 less than total
        }
        return requiredSecondaries;
    }

}
