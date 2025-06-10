package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

/**
 * Represents the response for a file-based MPIC (Multi-Perspective Corroboration) validation method.
 * This record encapsulates the primary file response, a list of secondary file responses,
 * the MPIC status, the number of agent corroborations, and any error message encountered.
 */
public record MpicFileResponse (PrimaryFileResponse primaryFileResponse,
                                List<SecondaryFileResponse> secondaryFileResponses,
                                MpicStatus mpicStatus,
                                long numAgentCorroborations,
                                String errorMessage) { }
