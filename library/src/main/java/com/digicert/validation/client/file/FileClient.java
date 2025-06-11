package com.digicert.validation.client.file;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.LogEvents;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.ConnectTimeoutException;
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
import org.slf4j.event.Level;

import javax.net.ssl.SSLContext;
import java.io.Closeable;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

/**
 * Client for handling file validation requests.
 * This client is configured with custom settings and a custom redirect strategy.
 * It uses Apache HttpClient for making HTTP requests.
 */
@Slf4j
public class FileClient implements Closeable {

    /** The log level used for logging errors related to domain control validation (DCV). */
    private final Level logLevelForDcvErrors;

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
     * Constructs a new FileClient with the specified configuration.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public FileClient(DcvContext dcvContext) {
        this.userAgent = dcvContext.getDcvConfiguration().getFileValidationUserAgent();
        this.maxBodyLength = dcvContext.getDcvConfiguration().getFileValidationMaxBodyLength();
        logLevelForDcvErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();
        this.dcvContext = dcvContext;
    }

    /**
     * Executes an HTTP GET request to the specified file URL.
     * <p>
     * If an exception occurs during the request or response processing, it is logged, and the appropriate error
     * information is set in the `FileClientResponse`.
     *
     * @param fileUrl The URL of the file to request.
     * @return A FileClientResponse containing either the response data or an exception if the request failed.
     */
    public FileClientResponse executeRequest(String fileUrl) {
        FileClientResponse clientResponse = new FileClientResponse(fileUrl);
        try {
            HttpGet request = new HttpGet(fileUrl);
            request.addHeader("User-Agent", userAgent);

            //noinspection resource
            createHttpClient().execute(request, fileResponse -> {
                try {
                    clientResponse.setStatusCode(fileResponse.getCode());
                    clientResponse.setFileContent(EntityUtils.toString(fileResponse.getEntity(), maxBodyLength));

                    if (clientResponse.getStatusCode() == 404){
                        clientResponse.setDcvError(DcvError.FILE_VALIDATION_NOT_FOUND);
                    } else if (clientResponse.getStatusCode() >= 400 && clientResponse.getStatusCode() < 500) {
                        clientResponse.setDcvError(DcvError.FILE_VALIDATION_CLIENT_ERROR);
                    } else if (clientResponse.getStatusCode() >= 500) {
                        clientResponse.setDcvError(DcvError.FILE_VALIDATION_SERVER_ERROR);
                    }

                    log.info("event_id={} url={} status_code={} length={}", LogEvents.FILE_VALIDATION_RESPONSE, fileUrl, fileResponse.getCode(), clientResponse.getFileContent().length());
                } catch (ParseException e) {
                    log.atLevel(logLevelForDcvErrors).log("event_id={} status_code={} exception_message={}", LogEvents.FILE_VALIDATION_BAD_RESPONSE, fileResponse.getCode(), e.getMessage());
                    clientResponse.setException(e);
                    clientResponse.setDcvError(DcvError.FILE_VALIDATION_INVALID_CONTENT);
                }
                return fileResponse;
            });
        } catch (ConnectTimeoutException e){
            // socket and connection timeouts are handled here
            log.atLevel(logLevelForDcvErrors).log("event_id={} exception_message={}", LogEvents.FILE_VALIDATION_CONNECTION_TIMEOUT_ERROR, e.getMessage());
            clientResponse.setException(e);
            clientResponse.setStatusCode(503);
            clientResponse.setDcvError(DcvError.FILE_VALIDATION_TIMEOUT);
        } catch (Exception e) {
            log.atLevel(logLevelForDcvErrors).log("event_id={} exception_message={}", LogEvents.FILE_VALIDATION_CLIENT_ERROR, e.getMessage());
            clientResponse.setException(e);
            clientResponse.setStatusCode(500);
            clientResponse.setDcvError(DcvError.FILE_VALIDATION_CLIENT_ERROR);
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
                .setMaxRedirects(dcvContext.getDcvConfiguration().getFileValidationMaxRedirects())
                .setConnectionRequestTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileValidationConnectTimeout()))
                .setResponseTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileValidationReadTimeout()))
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
                .setSoTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileValidationSocketTimeout()))
                .build();
    }

    /**
     * Creates a ConnectionConfig based on the specified configuration.
     *
     * @return A ConnectionConfig instance.
     */
    private ConnectionConfig getConnectionConfig() {
        return ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileValidationConnectTimeout()))
                .setSocketTimeout(Timeout.ofMilliseconds(dcvContext.getDcvConfiguration().getFileValidationSocketTimeout()))
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