package com.digicert.validation.client.fileauth;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.io.Closeable;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

/**
 * Client for handling file authentication requests.
 * This client is configured with custom settings and a custom redirect strategy.
 * It uses Apache HttpClient for making HTTP requests.
 */
@Slf4j
public class FileAuthClient implements Closeable {

    /** The HTTP client used to make requests. */
    private CloseableHttpClient httpClient;

    /**
     * The user agent to include in the request headers.
     * <p>
     * The `userAgent` string is included in the headers of each HTTP request made by this client.
     * It identifies the client software to the server.
     */
    private final String userAgent;

    /**
     * The maximum length of the response body to read.
     * <p>
     * The `maxBodyLength` is the maximum number of bytes to read from the response body.
     * If the response body is larger than this value, it is truncated.
     */
    private final int maxBodyLength;

    /**
     * The context where we can find the needed dependencies and configuration.
     * <p>
     * We are storing the context here, which allows for lazy initialization of the HTTP client.
     */
    private final DcvContext dcvContext;

    /**
     * Constructs a new FileAuthClient with the specified configuration.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public FileAuthClient(DcvContext dcvContext) {
        this.userAgent = dcvContext.getDcvConfiguration().getFileAuthUserAgent();
        this.maxBodyLength = dcvContext.getDcvConfiguration().getFileAuthMaxBodyLength();
        this.dcvContext = dcvContext;
    }

    /**
     * Executes an HTTP GET request to the specified file URL.
     * <p>
     * If an exception occurs during the request or response processing, it is logged, and the appropriate error
     * information is set in the `FileAuthClientResponse`.
     *
     * @param fileUrl The URL of the file to request.
     * @return A FileAuthClientResponse containing either the response data or an exception if the request failed.
     */
    public FileAuthClientResponse executeRequest(String fileUrl) {
        FileAuthClientResponse clientResponse = new FileAuthClientResponse(fileUrl);
        try {
            HttpGet request = new HttpGet(fileUrl);
            request.addHeader("User-Agent", userAgent);

            //noinspection resource
            createHttpClient().execute(request, fileResponse -> {
                try {
                    clientResponse.setStatusCode(fileResponse.getCode());
                    clientResponse.setFileContent(EntityUtils.toString(fileResponse.getEntity(), maxBodyLength));
                    log.info("event_id={} url={} status_code={} length={}", LogEvents.FILE_AUTH_RESPONSE, fileUrl, fileResponse.getCode(), clientResponse.getFileContent().length());
                } catch (ParseException e) {
                    log.info("event_id={} status_code={} exception_message={}", LogEvents.FILE_AUTH_BAD_RESPONSE, fileResponse.getCode(), e.getMessage());
                    clientResponse.setException(e);
                    clientResponse.setDcvError(DcvError.FILE_AUTH_INVALID_CONTENT);
                }
                return fileResponse;
            });
        } catch (Exception e) {
            log.info("event_id={} exception_message={}", LogEvents.FILE_AUTH_CLIENT_ERROR, e.getMessage());
            clientResponse.setException(e);
            clientResponse.setDcvError(DcvError.FILE_AUTH_CLIENT_ERROR);
        }
        return clientResponse;
    }

    /**
     * Creates an HTTP client with the specified configuration.
     * <p>
     * The HTTP client is created with a custom redirect strategy, a custom DNS resolver, and a custom SSL context.
     *
     * @return A CloseableHttpClient instance.
     */
    CloseableHttpClient createHttpClient() {
        if (httpClient == null) {
            httpClient = HttpClients.custom()
                    .setDefaultRequestConfig(getRequestConfig())
                    .setConnectionManager(getPoolingHttpClientConnectionManager())
                    .setRedirectStrategy(new CustomRedirectStrategy(dcvContext))
                    .build();
        }
        return httpClient;
    }

    /**
     * Creates a RequestConfig based on the specified configuration.
     *
     * @return A RequestConfig instance.
     */
    private RequestConfig getRequestConfig() {
        return RequestConfig.custom()
                .setRedirectsEnabled(true) // Enable redirects
                .setCircularRedirectsAllowed(false)
                .setMaxRedirects(dcvContext.getDcvConfiguration().getFileAuthMaxRedirects())
                .setConnectionRequestTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileAuthConnectTimeout()))
                .setResponseTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileAuthReadTimeout()))
                .setAuthenticationEnabled(false)
                .setCircularRedirectsAllowed(false)
                .build();
    }

    /**
     * Creates a PoolingHttpClientConnectionManager based on the specified configuration.
     *
     * @return A PoolingHttpClientConnectionManager instance.
     */
    private PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager() {
        return PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(getCustomDnsResolver())
                .setDefaultSocketConfig(getSocketConfig())
                .setConnectionConfigResolver(request -> getConnectionConfig())
                .setTlsSocketStrategy(new DefaultClientTlsStrategy(getSslContext()))
                .build();
    }

    /**
     * Creates a SocketConfig based on the specified configuration.
     *
     * @return A SocketConfig instance.
     */
    private SocketConfig getSocketConfig() {
        return SocketConfig.custom()
                .setSoTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileAuthSocketTimeout()))
                .build();
    }

    /**
     * Creates a ConnectionConfig based on the specified configuration.
     *
     * @return A ConnectionConfig instance.
     */
    private ConnectionConfig getConnectionConfig() {
        return ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileAuthConnectTimeout()))
                .setSocketTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileAuthSocketTimeout()))
                .build();
    }

    /**
     * Creates an SSLContext based on the specified configuration.
     *
     * @return An SSLContext instance.
     */
    private SSLContext getSslContext() {
        SSLContext sslContext;
        try {
            sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, TrustAllStrategy.INSTANCE)
                    .build();
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            log.error("event_id={}", LogEvents.SSL_CONTEXT_CREATION_ERROR, e);
            throw new IllegalStateException("Error creating SSL context", e);
        }
        return sslContext;
    }

    /**
     * Creates a CustomDnsResolver based on the specified configuration.
     * This method is package-private for testing purposes.
     *
     * @return A CustomDnsResolver instance.
     */
    CustomDnsResolver getCustomDnsResolver() {
        return dcvContext.get(CustomDnsResolver.class);
    }

    /**
     * Closes the HTTP client and releases any system resources associated with it.
     *
     * @throws IOException If an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (httpClient != null) {
            httpClient.close();
        }
    }
}