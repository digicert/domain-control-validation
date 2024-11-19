package com.digicert.validation.psl;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Objects;

/**
 * Provides access to Public Suffix List (PSL) data.
 * This class is implemented as a singleton.
 * <p>
 * The `PslDataProvider` class is responsible for managing and providing access to the Public Suffix List (PSL) data.
 * The PSL data is used to determine the domain suffixes that are considered public, which is essential for various
 * domain validation and security operations. This class ensures that only one instance of the PSL data is loaded
 * and provides methods to load, access, and reset the PSL data.
 */
@Getter
@Slf4j
public class PslDataProvider {

    /**
     * The singleton instance of the PslDataProvider.
     */
    private static final PslDataProvider INSTANCE = new PslDataProvider();

    /**
     * Private constructor to prevent instantiation.
     */
    private PslDataProvider() {}

    /**
     * Returns the singleton instance of the PslDataProvider.
     * <p>
     * This method provides access to the single instance of the `PslDataProvider` class. It ensures that the same
     * instance is returned every time it is called, maintaining the Singleton pattern. This method is thread-safe
     * and guarantees that only one instance of the class is created, even in a multithreaded environment.
     *
     * @return the singleton instance
     */
    public static PslDataProvider getInstance() {
        return INSTANCE;
    }

    /**
     * The PSL data.
     * <p>
     * This field holds the Public Suffix List (PSL) data that is loaded by the `PslDataProvider`. The PSL data is
     * essential for determining the public suffixes of domain names. This field is initialized when the PSL data
     * is loaded using the `loadPslData` or `loadDefaultData` methods.
     */
    private PslData pslData;

    /**
     * Loads PSL data from the provided reader.
     * <p>
     * This method loads the Public Suffix List (PSL) data from the provided `Reader` object. It uses the `PslDataParser`
     * to parse the data and initialize the `pslData` field. This method allows for flexibility in loading PSL data
     * from various sources, such as files, network streams, or other input sources.
     *
     * @param reader the reader to load PSL data from
     */
    public void loadPslData(Reader reader) {
        pslData = PslDataParser.parsePslData(reader);
    }

    /**
     * Loads the default PSL data from the resource file.
     * If PSL data is already loaded, this method does nothing.
     * <p>
     * This method loads the default Public Suffix List (PSL) data from a resource file included in the application's
     * classpath. If the PSL data is already loaded, the method does nothing to avoid reloading the data. If the
     * resource file cannot be found or an error occurs during loading, an `IllegalStateException` is thrown.
     *
     * @throws IllegalStateException if the default PSL data cannot be loaded
     */
    public void loadDefaultData() {
        if (pslData != null) {
            return;
        }

        InputStream resourceAsStream = Objects.requireNonNull(this.getClass().getClassLoader().getResourceAsStream("public_suffix_list.dat"));
        try (InputStreamReader reader = new InputStreamReader(resourceAsStream)) {
            loadPslData(reader);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load default PSL data", e);
        }
    }

    /**
     * Resets the PSL data, clearing any loaded data.
     * <p>
     * This method clears the currently loaded Public Suffix List (PSL) data by setting the `pslData` field to `null`.
     * This can be useful in scenarios where the PSL data needs to be reloaded or refreshed. After calling this method,
     * the `PslDataProvider` will need to load the PSL data again before it can be used.
     */
    void resetPslData() {
        pslData = null;
    }
}