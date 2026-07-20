package com.digicert.validation.mpic.api.file;


import com.digicert.validation.mpic.api.AgentStatus;

/**
 * Represents the response from a secondary file validation request.
 * Contains details about the agent, status, and whether it corroborates with the primary response.
 *
 * @param agentId      the identifier of the secondary MPIC agent
 * @param statusCode   the HTTP status code returned when fetching the file
 * @param agentStatus  the status reported by the agent for this file request
 * @param corroborates {@code true} if this secondary response corroborates the primary response
 */
public record SecondaryFileResponse(String agentId,
                                    int statusCode,
                                    AgentStatus agentStatus,
                                    boolean corroborates) {
}
