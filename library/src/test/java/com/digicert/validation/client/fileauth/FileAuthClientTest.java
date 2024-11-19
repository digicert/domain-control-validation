package com.digicert.validation.client.fileauth;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpError;
import org.mockserver.model.MediaType;
import org.mockserver.socket.PortFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;


@Slf4j
public class FileAuthClientTest {

    private static ClientAndServer mockServer;
    private FileAuthClient fileAuthClient;
    private static final String TOKEN_PATH = "/.well-known/pki-validation/";
    private CloseableHttpClient httpClientSpy;
    private CustomDnsResolver mockCustomDnsResolver;


    @BeforeAll
    public static void startServer() {
        mockServer = ClientAndServer.startClientAndServer(PortFactory.findFreePort());
    }

    @AfterAll
    public static void stopServer() {
        mockServer.stop();
    }

    @BeforeEach
    public void setUp() throws UnknownHostException {
        mockServer.reset();

        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .fileAuthUserAgent("testUserAgent")
                .dnsServers(List.of("localhost"))
                .build();
        DcvContext dcvContext = spy(new DcvContext(dcvConfiguration));

        // Configure the CustomDnsResolver to return localhost for any domain
        mockCustomDnsResolver = mock(CustomDnsResolver.class);
        when(mockCustomDnsResolver.resolve(any())).thenReturn(new InetAddress[]{InetAddress.getByName("localhost")});
        when(dcvContext.get(CustomDnsResolver.class)).thenReturn(mockCustomDnsResolver);
        doCallRealMethod().when(dcvContext).get(any());

        fileAuthClient = new FileAuthClient(dcvContext) {
            @Override
            CloseableHttpClient createHttpClient() {
                httpClientSpy = spy(super.createHttpClient());
                return httpClientSpy;
            }
        };
    }

    @Test
    void testFileAuthClient_Success() throws IOException {
        String expectedResponse = "Success";
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withStatusCode(200)
                        .withContentType(MediaType.TEXT_PLAIN)
                        .withBody(expectedResponse)
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(fileUrl, actualResponse.getFileUrl());
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());

        // Verify that the User-Agent header is set
        ArgumentCaptor<HttpGet> requestCaptor = ArgumentCaptor.forClass(HttpGet.class);
        verify(httpClientSpy).execute(requestCaptor.capture(), (HttpClientResponseHandler<?>) any());
        assertEquals("testUserAgent", requestCaptor.getValue().getFirstHeader("User-Agent").getValue());
    }

    @Test
    void testFileAuthClient_2xxStatusCode() {
        String expectedResponse = "Created";
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withStatusCode(201)
                        .withContentType(MediaType.TEXT_PLAIN)
                        .withBody(expectedResponse)
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileAuthClient_ResponseSizeLimit() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("123.45.67.89", "8.8.8.8"))
                .fileAuthMaxBodyLength(10)
                .build();

        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withContentType(MediaType.TEXT_PLAIN)
                        // Respond with a large body that exceeds the response size limit
                        .withBody("a".repeat(config.getFileAuthMaxBodyLength() * 2))
        );

        fileAuthClient = new FileAuthClient(new DcvContext(config));

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNull(actualResponse.getException());
        assertNull(actualResponse.getDcvError());
        assertEquals(200, actualResponse.getStatusCode());
        assertEquals(config.getFileAuthMaxBodyLength(), actualResponse.getFileContent().length());
    }

    @Test
    void testFileAuthClient_withCustomDnsResolver() {
        String domain = "my-cool-host.com";
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("123.45.67.89", "8.8.8.8"))
                .build();

        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        fileAuthClient = new FileAuthClient(dcvContext) {
            @Override
            CustomDnsResolver getCustomDnsResolver() {
                return mockCustomDnsResolver;
            }
        };

        String expectedResponse = "Created";
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withStatusCode(201)
                        .withContentType(MediaType.TEXT_PLAIN)
                        .withBody(expectedResponse)
        );

        String fileUrl = "http://" + domain + ":" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileAuthClient_Failure() {
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "nonexistent.txt")
        ).respond(
                response()
                        .withStatusCode(404)
                        .withContentType(MediaType.TEXT_PLAIN)
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "nonexistent.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(404, actualResponse.getStatusCode());
        assertEquals("", actualResponse.getFileContent());
    }

    @Test
    void testFileAuthClient_Timeout() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("123.45.67.89", "8.8.8.8"))
                .fileAuthReadTimeout(5)
                .build();

        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "timeout.txt")
        ).respond(
                httpRequest -> {
                    try {
                        Thread.sleep(config.getFileAuthConnectTimeout() * 2L);
                    } catch (InterruptedException e) {
                        log.info("Thread interrupted", e);
                    }
                    return response()
                            .withStatusCode(200)
                            .withContentType(MediaType.TEXT_PLAIN)
                            .withBody("This should not be returned");
                }
        );

        fileAuthClient = new FileAuthClient(new DcvContext(config));

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "timeout.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(0, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertInstanceOf(SocketTimeoutException.class, actualResponse.getException());
    }

    @Test
    void testFileAuthClient_ThrowException() {
        // throw exception when endpoint is called
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "timeout.txt")
        ).error(new HttpError());

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "timeout.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(0, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertNotNull(actualResponse.getException());
        assertInstanceOf(SocketTimeoutException.class, actualResponse.getException());
        assertEquals(DcvError.FILE_AUTH_CLIENT_ERROR, actualResponse.getDcvError());
    }

    @Test
    void testFileAuthClient_withCustomDnsResolver_SecondServer_FirstServerEmptyValue() {
        String domain = "my-cool-host.com";
            DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("", "8.8.8.8"))
                .build();

        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        fileAuthClient = new FileAuthClient(dcvContext) {
            @Override
            CustomDnsResolver getCustomDnsResolver() {
                return mockCustomDnsResolver;
            }
        };

        String expectedResponse = "Created";
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withStatusCode(201)
                        .withContentType(MediaType.TEXT_PLAIN)
                        .withBody(expectedResponse)
        );

        String fileUrl = "http://" + domain +  ":" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileAuthClient_cicularRedirects_disallowed() {
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "redirect1.txt")
        ).respond(
                response()
                        .withStatusCode(301)
                        .withHeader("Location", TOKEN_PATH + "redirect2.txt")
        );
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "redirect2.txt")
        ).respond(
                response()
                        .withStatusCode(301)
                        .withHeader("Location", TOKEN_PATH + "redirect1.txt")
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "redirect1.txt";
        FileAuthClientResponse actualResponse = fileAuthClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(0, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertTrue(actualResponse.getException().getMessage().contains("Circular redirect"));
    }
}