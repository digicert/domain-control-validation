package com.digicert.validation.client.file;

import java.net.URI;
import java.util.List;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.utils.DomainNameUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;

/**
 * This class extends the DefaultRedirectStrategy to offer more control over the redirection process
 * to follow BR requirements.
 */
@Slf4j
public class CustomRedirectStrategy extends DefaultRedirectStrategy {

    /**
     * The list of BR allowed redirect status codes.
     * <ul>
     * <li>301 (Moved Permanently)</li>
     * <li>302 (Found)</li>
     * <li>307 (Temporary Redirect)</li>
     * <li>308 (Permanent Redirect)</li>
     * </ul>
     */
    private static final List<Integer> ALLOWED_REDIRECTS = List.of(301, 302, 307, 308);

    /**
     * A DomainNameUtils instance used to determine if a redirect has the same base domain as the original url.
     */
    private final DomainNameUtils domainNameUtils;

    /**
     * Constructs a new CustomRedirectStrategy.
     *
     * @param dcvContext The DcvContext instance to use.
     * */
    public CustomRedirectStrategy(DcvContext dcvContext) {
        this.domainNameUtils = dcvContext.get(DomainNameUtils.class);
    }

    /**
     * Determines if a request should be redirected based on the response status code and the original and new URLs.
     * <p>
     * Redirects can only be followed if the response status code is one of the allowed redirect status codes
     * (301, 302, 307, 308). Additionally, redirects must be over HTTP on port 80 or HTTPS on port 443.
     * <p>
     * The location must share the same base domain as the original URL.
     *
     * @param request  The original HTTP request.
     * @param response The HTTP response.
     * @param context  The HTTP context.
     * @return true if the request should be redirected, false otherwise.
     */
    @Override
    public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context) {
        int statusCode = response.getCode();

        if (!ALLOWED_REDIRECTS.contains(statusCode)) {
            return false;
        }

        String originalUrl = request.getRequestUri();
        String newLocationUrl = response.getFirstHeader("Location").getValue();

        return shouldFollowRedirect(originalUrl, newLocationUrl);
    }

    /**
     * Determines if a redirect should be followed based on the original and new URLs.
     *
     * @param originalUrl    The original URL.
     * @param newLocationUrl The new location URL.
     * @return true if the redirect should be followed, false otherwise.
     */
    boolean shouldFollowRedirect(String originalUrl, String newLocationUrl) {
        if (originalUrl == null || newLocationUrl == null) {
            return false;
        }

        URI locationURI;
        try {
            locationURI = URI.create(newLocationUrl);
        } catch (Exception e) {
            log.info("event_id={} location={} sourceUrl={}", LogEvents.BAD_REDIRECT_URL, newLocationUrl, originalUrl);
            return false;
        }

        if (!locationURI.isAbsolute()) {
            return true;
        }
        return validateRedirectHost(newLocationUrl, originalUrl);
    }

    /**
     * Validates if the redirect URL is appropriate based on the source URL.
     *
     * @param redirectTo The URL to redirect to.
     * @param sourceUrl  The original source URL.
     * @return true if the redirect URL is valid, false otherwise.
     */
    boolean validateRedirectHost(String redirectTo, String sourceUrl) {
        try {
            URI redirectURI = new URI(redirectTo);
            String host = redirectURI.getHost();
            if (host == null) {
                log.warn("event_id={} location={} sourceUrl={}", LogEvents.BAD_REDIRECT_NO_HOST, redirectTo, sourceUrl);
                return false;
            }
            if (!portMatchesScheme(redirectURI)) {
                log.warn("event_id={} location={} sourceUrl={}", LogEvents.BAD_REDIRECT_PORT, redirectTo, sourceUrl);
                return false;
            }

            return StringUtils.equals(domainNameUtils.getBaseDomain(host), domainNameUtils.getBaseDomain(new URI(sourceUrl).getHost()));
        } catch (Exception e) {
            log.error("event_id={} sourceUrl={} redirectUrl={}", LogEvents.REDIRECT_ERROR, sourceUrl, redirectTo, e);
            return false;
        }
    }

    /**
     * Checks if the port in the URI matches the scheme (http or https).
     *
     * @param uri The URI to check.
     * @return true if the port matches the scheme, false otherwise.
     */
    private boolean portMatchesScheme(URI uri) {
        if (uri.getPort() == -1) {
            // no port specified -> it's the default port for the scheme
            return true;
        }
        return switch (uri.getScheme()) {
            case "http" -> uri.getPort() == 80;
            case "https" -> uri.getPort() == 443;
            default -> false; // MUST be retrieved via either the "http" or "https" scheme -> can't redirect to a different scheme
        };
    }
}