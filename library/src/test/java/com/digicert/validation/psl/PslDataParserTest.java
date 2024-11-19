package com.digicert.validation.psl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class PslDataParserTest {

    // Test case for parsing PSL data
    @Test
    void testParsePslData() throws IOException {
        InputStream resourceAsStream = Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("public_suffix_list_test.dat"));
        try (InputStreamReader inputStreamReader = new InputStreamReader(resourceAsStream)) {

            PslData pslData = PslDataParser.parsePslData(inputStreamReader);

            assertNotNull(pslData);
            assertNotNull(pslData.getRegistrySuffixTrie());
            assertNotNull(pslData.getRegistryWildcardTrie());
            assertNotNull(pslData.getRegistryExceptionTrie());
        }
    }
}