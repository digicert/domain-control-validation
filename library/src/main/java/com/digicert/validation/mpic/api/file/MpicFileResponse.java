package com.digicert.validation.mpic.api.file;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

public record MpicFileResponse (PrimaryFileResponse primaryFileResponse,
                                List<SecondaryFileResponse> secondaryFileResponses,
                                MpicStatus mpicStatus,
                                long numAgentCorroborations,
                                String errorMessage) { }
