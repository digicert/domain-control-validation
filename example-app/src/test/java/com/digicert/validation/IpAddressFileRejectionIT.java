package com.digicert.validation;

import com.digicert.validation.client.ExampleAppClient;
import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.request.DcvRequestType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests that verify reserved and private IP addresses are rejected by the
 * DCV library when {@code allowReservedIpAddresses} is {@code false} (the default).
 * <p>
 * This class uses the production {@link ExampleDCVConfiguration} — no
 * {@code AllowReservedIpDcvConfiguration} is imported — so the library enforces the
 * CA/Browser Forum Baseline Requirements check that rejects private/reserved IP space.
 * <p>
 * A submission of any reserved IP address must return a non-2xx HTTP response (HTTP 400).
 *
 * @see IpAddressFileMethodIT for happy-path IP address file validation tests
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class IpAddressFileRejectionIT {

    @Autowired
    private ExampleAppClient exampleAppClient;

    private static final Long defaultAccountId = 1234L;

    @ParameterizedTest(name = "{0} is rejected")
    @MethodSource("provideReservedIpAddresses")
    void verifyFileValidation_reservedIpAddress_isRejected(String description, String ipAddress) {
        DcvRequest dcvRequest = new DcvRequest(ipAddress, defaultAccountId, DcvRequestType.FILE_VALIDATION);
        assertTrue(exampleAppClient.submitDnsDomainExpectingFail(dcvRequest));
    }

    private static Stream<Arguments> provideReservedIpAddresses() {
        return Stream.of(
                Arguments.of("RFC 1918 class-A private IPv4 (10.0.0.1)",    "10.0.0.1"),
                Arguments.of("RFC 1918 class-B private IPv4 (172.16.0.1)",  "172.16.0.1"),
                Arguments.of("RFC 1918 class-C private IPv4 (192.168.1.1)", "192.168.1.1"),
                Arguments.of("loopback IPv4 (127.0.0.1)",                   "127.0.0.1"),
                Arguments.of("link-local IPv4 (169.254.1.1)",               "169.254.1.1"),
                Arguments.of("multicast IPv4 (224.0.0.1)",                  "224.0.0.1"),
                Arguments.of("loopback IPv6 (::1)",                         "::1"),
                Arguments.of("link-local IPv6 (fe80::1)",                   "fe80::1"),
                Arguments.of("ULA IPv6 (fc00::1)",                          "fc00::1")
        );
    }
}
