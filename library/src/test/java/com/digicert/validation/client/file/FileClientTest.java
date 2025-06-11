package com.digicert.validation.client.file;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.ClientProtocolException;
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
public class FileClientTest {

    private static ClientAndServer mockServer;
    private FileClient fileClient;
    private static final String TOKEN_PATH = "/.well-known/pki-validation/";
    private CloseableHttpClient httpClientSpy;
    private CustomDnsResolver mockCustomDnsResolver;
    private DcvContext dcvContext;

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
                .fileValidationUserAgent("testUserAgent")
                .dnsServers(List.of("localhost"))
                .build();
        dcvContext = spy(new DcvContext(dcvConfiguration));

        // Configure the CustomDnsResolver to return localhost for any domain
        mockCustomDnsResolver = mock(CustomDnsResolver.class);
        when(mockCustomDnsResolver.resolve(any())).thenReturn(new InetAddress[]{InetAddress.getByName("localhost")});
        when(dcvContext.get(CustomDnsResolver.class)).thenReturn(mockCustomDnsResolver);

        fileClient = new FileClient(dcvContext) {
            @Override
            CloseableHttpClient createHttpClient() {
                httpClientSpy = spy(super.createHttpClient());
                return httpClientSpy;
            }
        };
    }

    @Test
    void testFileClient_Success() throws IOException {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

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
    void testFileClient_2xxStatusCode() {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileClient_ResponseSizeLimit() throws UnknownHostException {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("localhost"))
                .fileValidationMaxBodyLength(10)
                .build();

        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "fileauth.txt")
        ).respond(
                response()
                        .withContentType(MediaType.TEXT_PLAIN)
                        // Respond with a large body that exceeds the response size limit
                        .withBody("a".repeat(config.getFileValidationMaxBodyLength() * 2))
        );

        dcvContext = spy(new DcvContext(config));

        // Configure the CustomDnsResolver to return localhost for any domain
        mockCustomDnsResolver = mock(CustomDnsResolver.class);
        when(mockCustomDnsResolver.resolve(any())).thenReturn(new InetAddress[]{InetAddress.getByName("localhost")});
        when(dcvContext.get(CustomDnsResolver.class)).thenReturn(mockCustomDnsResolver);

        fileClient = new FileClient(dcvContext) {
            @Override
            CloseableHttpClient createHttpClient() {
                httpClientSpy = spy(super.createHttpClient());
                return httpClientSpy;
            }
        };

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "fileauth.txt";
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNull(actualResponse.getException());
        assertNull(actualResponse.getDcvError());
        assertEquals(200, actualResponse.getStatusCode());
        assertEquals(config.getFileValidationMaxBodyLength(), actualResponse.getFileContent().length());
    }

    @Test
    void testFileClient_withCustomDnsResolver() {
        String domain = "my-cool-host.com";
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("localhost"))
                .build();

        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        fileClient = new FileClient(dcvContext) {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileClient_Failure() {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(404, actualResponse.getStatusCode());
        assertEquals("", actualResponse.getFileContent());
    }

    @Test
    void testFileClient_Timeout() throws UnknownHostException {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("localhost"))
                .fileValidationReadTimeout(5)
                .build();

        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "timeout.txt")
        ).respond(
                httpRequest -> {
                    try {
                        Thread.sleep(config.getFileValidationConnectTimeout() * 2L);
                    } catch (InterruptedException e) {
                        log.info("Thread interrupted", e);
                    }
                    return response()
                            .withStatusCode(200)
                            .withContentType(MediaType.TEXT_PLAIN)
                            .withBody("This should not be returned");
                }
        );

        dcvContext = spy(new DcvContext(config));

        // Configure the CustomDnsResolver to return localhost for any domain
        mockCustomDnsResolver = mock(CustomDnsResolver.class);
        when(mockCustomDnsResolver.resolve(any())).thenReturn(new InetAddress[]{InetAddress.getByName("localhost")});
        when(dcvContext.get(CustomDnsResolver.class)).thenReturn(mockCustomDnsResolver);

        fileClient = new FileClient(dcvContext) {
            @Override
            CloseableHttpClient createHttpClient() {
                httpClientSpy = spy(super.createHttpClient());
                return httpClientSpy;
            }
        };

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "timeout.txt";
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(500, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertInstanceOf(SocketTimeoutException.class, actualResponse.getException());
    }

    @Test
    void testFileClient_ThrowException() {
        // throw exception when endpoint is called
        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "timeout.txt")
        ).error(new HttpError());

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "timeout.txt";
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(500, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertNotNull(actualResponse.getException());
        assertInstanceOf(SocketTimeoutException.class, actualResponse.getException());
        assertEquals(DcvError.FILE_VALIDATION_CLIENT_ERROR, actualResponse.getDcvError());
    }

    @Test
    void testFileClient_withCustomDnsResolver_SecondServer_FirstServerEmptyValue() {
        String domain = "my-cool-host.com";
            DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsServers(List.of("", "8.8.8.8"))
                .build();

        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        fileClient = new FileClient(dcvContext) {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse.getFileContent());
        assertNull(actualResponse.getException());
    }

    @Test
    void testFileClient_cicularRedirects_disallowed() {
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
        FileClientResponse actualResponse = fileClient.executeRequest(fileUrl);

        assertNotNull(actualResponse);
        assertEquals(500, actualResponse.getStatusCode());
        assertNull(actualResponse.getFileContent());
        assertTrue(actualResponse.getException() instanceof ClientProtocolException);
        assertTrue(actualResponse.getException().getMessage().contains("Circular redirect"));
    }

    @Test
    void testGetFileData_ServerError(){

        mockServer.when(
                request()
                        .withMethod("GET")
                        .withPath(TOKEN_PATH + "file.txt")
        ).respond(
                response()
                        .withStatusCode(500)
                        .withContentType(MediaType.TEXT_PLAIN)
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "file.txt";
        FileClientResponse fileClientResponse = fileClient.executeRequest(fileUrl);

        assertEquals(500, fileClientResponse.getStatusCode());
        assertEquals(fileUrl, fileClientResponse.getFileUrl());
        assertNull(fileClientResponse.getException());
        assertEquals(DcvError.FILE_VALIDATION_SERVER_ERROR, fileClientResponse.getDcvError());
    }

    @Test
    void testGetFileData_ClientError() {
        mockServer.when(
                request()
                    .withMethod("GET")
                    .withPath(TOKEN_PATH + "file.txt")
        ).respond(
                response()
                        .withStatusCode(400)
                        .withContentType(MediaType.TEXT_PLAIN)
        );

        String fileUrl = "http://localhost:" + mockServer.getLocalPort() + TOKEN_PATH + "file.txt";
        FileClientResponse fileClientResponse = fileClient.executeRequest(fileUrl);

        assertEquals(400, fileClientResponse.getStatusCode());
        assertEquals(fileUrl, fileClientResponse.getFileUrl());
        assertEquals(DcvError.FILE_VALIDATION_CLIENT_ERROR, fileClientResponse.getDcvError());
    }
}