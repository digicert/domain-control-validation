package com.digicert.validation.mpic.api.file;


import com.digicert.validation.mpic.api.AgentStatus;

public record SecondaryFileResponse(String agentId,
                                    int statusCode,
                                    AgentStatus agentStatus,
                                    boolean corroborates) { }
