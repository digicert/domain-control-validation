package com.digicert.validation.methods.acme.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.AcmeValidationException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.file.validate.MpicFileDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.MpicFileService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.event.Level;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/** Handles ACME validation processes. */
@Slf4j
public class AcmeValidationHandler {

    private final static String ACME_DNS_PREFIX = "_acme-challenge.";
    private final static String ACME_HTTP_URL_TEMPLATE = "http://%s/.well-known/acme-challenge/%s";

    /** The MPIC service used to fetch DNS details. */
    private final MpicDnsService mpicDnsService;

    /** The MPIC service used to fetch FILE details. */
    private final MpicFileService mpicFileService;

    /** The log level used for logging errors related to domain control validation (DCV). */
    private final Level logLevelForDcvErrors;
    /**
     * Constructs a new AcmeValidationHandler with the specified configuration.
     *
     * @param dcvContext context where we can find the necessary dependencies / configuration
     */
    public AcmeValidationHandler(DcvContext dcvContext) {
        this.mpicDnsService = dcvContext.get(MpicDnsService.class);
        this.mpicFileService = dcvContext.get(MpicFileService.class);
        this.logLevelForDcvErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();
    }

    /**
     * This method performs the ACME validation based on the given ACME validation request.
     *
     * @param request the DNS validation request
     * @return the ACME validation response
     */
    public AcmeValidationResponse validate(AcmeValidationRequest request) throws ValidationException {
        return switch (request.getAcmeType()) {
            case ACME_DNS_01 -> validateUsingAcmeDns(request);
            case ACME_HTTP_01 -> validateUsingAcmeHttp(request);
        };
    }

    private AcmeValidationResponse validateUsingAcmeHttp(AcmeValidationRequest request) throws ValidationException {
        String acmeUrl = String.format(ACME_HTTP_URL_TEMPLATE, request.getDomain(), request.getRandomValue());
        MpicFileDetails mpicFileDetails = mpicFileService.getMpicFileDetails(List.of(acmeUrl));

        if (mpicFileDetails.dcvError() != null) {
            // If the MPIC file details contain an error, we will throw an exception
            log.atLevel(logLevelForDcvErrors).log("event_id={} acme_url={} domain={} reason={}",
                    LogEvents.ACME_VALIDATION_FAILED, acmeUrl, request.getDomain(), mpicFileDetails.dcvError());
            throw new AcmeValidationException(mpicFileDetails.dcvError(), request);
        }

        String keyAuthorization = request.getRandomValue() + "." + request.getAcmeThumbprint();
        if (!mpicFileDetails.fileContents().trim().equals(keyAuthorization)) {
            // If the file contents do not match the key authorization, we will throw an exception
            log.atLevel(logLevelForDcvErrors).log("event_id={} acme_url={} domain={} key_authorization={} reason={}",
                    LogEvents.ACME_VALIDATION_FAILED, acmeUrl, request.getDomain(), keyAuthorization, DcvError.RANDOM_VALUE_NOT_FOUND);
            throw new AcmeValidationException(DcvError.RANDOM_VALUE_NOT_FOUND, request);
        }

        return new AcmeValidationResponse(mpicFileDetails.mpicDetails(), null, acmeUrl);
    }

    private AcmeValidationResponse validateUsingAcmeDns(AcmeValidationRequest request) throws ValidationException {
        String computedDnsTxtValue = calculateDnsTxtValue(request);
        String dnsRecordName = ACME_DNS_PREFIX + request.getDomain();

        MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(dnsRecordName, DnsType.TXT);
        if (mpicDnsDetails.dcvError() != null) {
            // If the MPIC file details contain an error, we will not throw an exception
            log.atLevel(logLevelForDcvErrors).log("event_id={} domain={} reason={}",
                    LogEvents.ACME_VALIDATION_FAILED, request.getDomain(), mpicDnsDetails.dcvError());
            throw new AcmeValidationException(mpicDnsDetails.dcvError(), request);
        }

        boolean isValid = mpicDnsDetails.dnsRecords().stream()
                .map(DnsRecord::value)
                .filter(dnsValue -> !StringUtils.isEmpty(dnsValue))
                .anyMatch(dnsValue -> dnsValue.contains(computedDnsTxtValue));
        if (!isValid) {
            log.atLevel(logLevelForDcvErrors).log("event_id={} domain={} reason={}",
                    LogEvents.ACME_VALIDATION_FAILED, request.getDomain(), DcvError.RANDOM_VALUE_NOT_FOUND);
            throw new AcmeValidationException(DcvError.RANDOM_VALUE_NOT_FOUND, request);
        }

        return new AcmeValidationResponse(mpicDnsDetails.mpicDetails(), dnsRecordName, null);
    }

    private String calculateDnsTxtValue(AcmeValidationRequest request) throws ValidationException {
        String keyAuthorization = request.getRandomValue() + "." + request.getAcmeThumbprint();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(keyAuthorization.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new AcmeValidationException(DcvError.ACME_DNS_KEY_ERROR, request);
        }
    }
}