package com.digicert.validation.utils;

import java.util.regex.Pattern;

/**
 * Utility class for validating filenames.
 * <p>
 * The `FilenameUtils` class provides static methods for validating filenames.
 * It ensures that filenames contain only allowed characters and do not exceed
 * a maximum length. This class is useful for validating filenames before
 * using them in file operations or storage.
 */
public class FilenameUtils {
    /** Regex for one or more of the allowed char set for filename. */
    private static final Pattern FILENAME_CHAR_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /**
     * Private constructor to prevent instantiation.
     */
    private FilenameUtils() {}

    /**
     * Validates a filename to ensure it contains only allowed characters
     * and does not exceed a maximum length.
     *
     * @param fileAuthFileName the filename to validate
     * @throws IllegalArgumentException if the filename is null, empty, contains
     *                                  invalid characters, or exceeds the maximum length
     */
    public static void validateFilename(String fileAuthFileName) throws IllegalArgumentException {
        if (fileAuthFileName == null || fileAuthFileName.isEmpty()) {
            throw new IllegalArgumentException("fileAuthFileName cannot be null or empty");
        }
        if (!FILENAME_CHAR_PATTERN.matcher(fileAuthFileName).matches()) {
            throw new IllegalArgumentException("fileAuthFileName contains invalid characters");
        }

        // Validate file name length
        int maxLength = 64;
        if (fileAuthFileName.length() > maxLength) {
            throw new IllegalArgumentException("fileAuthFileName exceeds maximum length of " + maxLength);
        }
    }
}