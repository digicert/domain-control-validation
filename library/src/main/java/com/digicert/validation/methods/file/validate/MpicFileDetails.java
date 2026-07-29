package com.digicert.validation.methods.file.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;

/**
 * Represents the details of a file used for MPIC (Multi-Perspective Corroboration)
 * validation, including the MPIC details, file URL, file content, status code, and any
 * associated error.
 *
 * @param mpicDetails  the MPIC corroboration summary for this file validation
 * @param fileUrl      the URL of the file that was fetched
 * @param fileContents the contents of the fetched file
 * @param statusCode   the HTTP status code returned when fetching the file
 * @param dcvError     any DCV error encountered during file retrieval, or {@code null} if none
 */
public record MpicFileDetails(MpicDetails mpicDetails,
                              String fileUrl,
                              String fileContents,
                              int statusCode,
                              DcvError dcvError) { }
