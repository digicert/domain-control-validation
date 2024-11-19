package com.digicert.validation.client.file;

import com.digicert.validation.DcvContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class CustomRedirectStrategyTest {
    private final CustomRedirectStrategy sut = new CustomRedirectStrategy(new DcvContext());

    static Stream<Arguments> redirects_testData() {
        return Stream.of(
                // Test cases for null values
                Arguments.of(null, "http://example.com", false),
                Arguments.of("http://example.com", null, false),

                // Test case for relative url
                Arguments.of("http://example.com", "/new-location", true),
                Arguments.of("http://example.com", "example.com/new-location", true),

                // Test cases for http over various ports
                Arguments.of("http://example.com", "http://example.com/new-location", true),
                Arguments.of("http://example.com", "http://example.com:80/new-location", true),
                Arguments.of("http://example.com", "http://example.com:443/new-location", false),
                Arguments.of("http://example.com", "http://example.com:8080/new-location", false),

                // Test cases for https over various ports
                Arguments.of("http://example.com", "https://example.com", true),
                Arguments.of("http://example.com", "https://example.com:443", true),
                Arguments.of("http://example.com", "https://example.com:443/new-location", true),
                Arguments.of("http://example.com", "https://example.com:80", false),
                Arguments.of("http://example.com", "https://example.com:8443", false),

                // Test cases around base domain matching
                Arguments.of("http://example.com", "http://sub.example.com/location", true),
                Arguments.of("http://sub.example.com", "http://example.com/location", true),
                Arguments.of("http://example.com", "http://foobar.com/location", false),
                Arguments.of("http://example.co.uk", "http://example.uk", false),

                // Test cases for invalid urls
                Arguments.of("http://example.com", "http://[invalid.url]", false)
        );
    }

    @ParameterizedTest
    @MethodSource("redirects_testData")
    void testCustomRedirectStrategy_shouldFollowRedirect(String originalUrl, String newLocationUrl, boolean expectedResult) {
        assertEquals(expectedResult, sut.shouldFollowRedirect(originalUrl, newLocationUrl));
    }
}