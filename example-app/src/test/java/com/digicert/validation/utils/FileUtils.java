package com.digicert.validation.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtils {

    public static final String FILE_AUTH_DIRECTORY_PATH = "./nginx/www/.well-known/pki-validation/";
    public static final String ACME_HTTP_DIRECTORY_PATH = "./nginx/www/.well-known/acme-challenge/";

    public static void writeFileAuthFileWithContent(String fileName, String content) throws IOException {
        // Create the file
        File file = new File(FILE_AUTH_DIRECTORY_PATH + fileName);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    public static void writeAcmeHttpFileWithContent(String fileName, String content) throws IOException {
        // Create the file
        File file = new File(ACME_HTTP_DIRECTORY_PATH + fileName);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}
