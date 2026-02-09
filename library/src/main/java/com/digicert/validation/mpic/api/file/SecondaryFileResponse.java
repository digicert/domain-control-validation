package com.digicert.validation.mpic.api.file;


import com.digicert.validation.mpic.api.AgentStatus;

/**
 * Represents the response from a secondary file validation request.
 * Contains details about the agent, status, and whether it corroborates with the primary response.
 */
public record SecondaryFileResponse(String agentId,
                                    int statusCode,
                                    AgentStatus agentStatus,
                                    boolean corroborates) {
}
