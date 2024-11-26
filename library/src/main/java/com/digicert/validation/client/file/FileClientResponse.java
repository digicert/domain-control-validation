package com.digicert.validation.client.file;

import com.digicert.validation.enums.DcvError;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Represents the response from a file validation client.
 */
@AllArgsConstructor
@Getter
@Setter
@ToString
public class FileClientResponse {
    /** The URL of the file requested. */
    private String fileUrl;

    /** The content of the requested file. */
    private String fileContent;

    /** The final HTTP status code after all redirects have been processed. */
    private int statusCode;

    /** The exception that occurred during the file validation process, if any. */
    private Exception exception;

    /**
     * The DCV error that occurred during the file validation process, if any.
     * <p>
     * If set this field will be one of the following:
     * <ul>
     *     <li>FILE_VALIDATION_CLIENT_ERROR</li>
     *     <li>FILE_VALIDATION_INVALID_CONTENT</li>
     * </ul>
     */
    private DcvError dcvError;

    /**
     * Constructs a new FileClientResponse with the specified file URL.
     * The content, status code, exception, and DCV error are set to null.
     *
     * @param fileUrl the URL of the file
     */
    public FileClientResponse(String fileUrl) {
        this.fileUrl = fileUrl;
    }

    /**
     * Constructs a new FileClientResponse with the specified file URL and content.
     * The exception is set to null.
     *
     * @param fileUrl     the URL of the file
     * @param fileContent the content of the file
     * @param statusCode  the status code of the HTTP response
     */
    public FileClientResponse(String fileUrl, String fileContent, int statusCode) {
        this.fileUrl = fileUrl;
        this.fileContent = fileContent;
        this.statusCode = statusCode;
        this.exception = null;
    }
}