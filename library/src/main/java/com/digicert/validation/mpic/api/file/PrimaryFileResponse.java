package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.dns.DnssecDetails;

/**
 * Represents the response from a primary file validation request.
 * Contains details about the agent, status, file URL, file contents, and DNSSEC details.
 */
public record PrimaryFileResponse(String agentId,
                                  int statusCode,
                                  AgentStatus agentStatus,
                                  String fileUrl,
                                  String actualFileUrl,
                                  String fileContents,
                                  DnssecDetails dnssecDetails) {

    /** Backward-compatible constructor that defaults dnssecDetails to null. */
    public PrimaryFileResponse(String agentId,
                               int statusCode,
                               AgentStatus agentStatus,
                               String fileUrl,
                               String actualFileUrl,
                               String fileContents) {
        this(agentId, statusCode, agentStatus, fileUrl, actualFileUrl, fileContents, null);
    }
}
