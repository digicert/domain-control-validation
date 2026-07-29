package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.AgentStatus;

/**
 * Represents the response from a primary file validation request.
 * Contains details about the agent, status, file URL, and file contents.
 *
 * @param agentId        the identifier of the primary MPIC agent
 * @param statusCode     the HTTP status code returned when fetching the file
 * @param agentStatus    the status reported by the agent for this file request
 * @param fileUrl        the URL of the file that was fetched
 * @param actualFileUrl  the actual URL after any redirects
 * @param fileContents   the contents of the fetched file
 */
public record PrimaryFileResponse(String agentId,
                                  int statusCode,
                                  AgentStatus agentStatus,
                                  String fileUrl,
                                  String actualFileUrl,
                                  String fileContents) {
}
