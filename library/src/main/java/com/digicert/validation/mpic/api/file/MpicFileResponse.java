package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

/**
 * Represents the response for a file-based MPIC (Multi-Perspective Corroboration) validation method.
 * This record encapsulates the primary file response, a list of secondary file responses,
 * the MPIC status, the number of agent corroborations, and any error message encountered.
 *
 * @param primaryFileResponse      the response from the primary MPIC agent
 * @param secondaryFileResponses   the responses from secondary MPIC agents
 * @param mpicStatus               the overall MPIC corroboration status
 * @param numAgentCorroborations   the number of agents that corroborated the primary response
 * @param errorMessage             an error message if the MPIC request failed, or {@code null} if none
 */
public record MpicFileResponse (PrimaryFileResponse primaryFileResponse,
                                List<SecondaryFileResponse> secondaryFileResponses,
                                MpicStatus mpicStatus,
                                long numAgentCorroborations,
                                String errorMessage) { }
