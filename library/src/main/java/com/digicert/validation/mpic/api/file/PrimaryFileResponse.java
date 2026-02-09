package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.AgentStatus;

/**
 * Represents the response from a primary file validation request.
 * Contains details about the agent, status, file URL, and file contents.
 */
public record PrimaryFileResponse(String agentId,
                                  int statusCode,
                                  AgentStatus agentStatus,
                                  String fileUrl,
                                  String actualFileUrl,
                                  String fileContents) {
}
