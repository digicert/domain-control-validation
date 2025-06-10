package com.digicert.validation.methods.file.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;

/**
 * Represents the details of a file used for MPIC (Multi-Perspective Corroboration)
 * validation, including the MPIC details, file URL, file content, status code, and any
 * associated error.
 */
public record MpicFileDetails(MpicDetails mpicDetails,
                              String fileUrl,
                              String fileContent,
                              int statusCode,
                              DcvError dcvError) { }
