package com.digicert.validation.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtils {

    private static final String DIRECTORY_PATH = "./nginx/www/.well-known/pki-validation/";

    public static void writeNginxStaticFileWithContent(String fileName, String content) throws IOException {
        // Create the file
        File file = new File(DIRECTORY_PATH + fileName);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}
