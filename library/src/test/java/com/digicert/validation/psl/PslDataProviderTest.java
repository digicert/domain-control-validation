package com.digicert.validation.psl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

class PslDataProviderTest {

    private PslDataProvider pslDataProvider;

    @BeforeEach
    void setUp() {
        pslDataProvider = PslDataProvider.getInstance();
    }

    @Test
    void testLoadDefaultPslData() {
        pslDataProvider.loadDefaultData();
        PslData pslData = pslDataProvider.getPslData();

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistrySuffixTrie());
        assertNotNull(pslData.getRegistryWildcardTrie());
        assertNotNull(pslData.getRegistryExceptionTrie());
    }

    @Test
    void testLoadPslData() {
        pslDataProvider.resetPslData();
        pslDataProvider.loadPslData(getInputStreamReader());
        PslData pslData = pslDataProvider.getPslData();

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistrySuffixTrie());
        assertNotNull(pslData.getRegistryWildcardTrie());
        assertNotNull(pslData.getRegistryExceptionTrie());
    }

    private InputStreamReader getInputStreamReader() {
        InputStream resourceAsStream = Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("public_suffix_list_test.dat"));
        return new InputStreamReader(resourceAsStream);
    }
}