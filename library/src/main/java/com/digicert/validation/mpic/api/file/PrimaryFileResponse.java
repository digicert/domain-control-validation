package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.AgentStatus;

public record PrimaryFileResponse(String agentId,
                                  int statusCode,
                                  AgentStatus agentStatus,
                                  String fileUrl,
                                  String actualFileUrl,
                                  String fileContents) { }
