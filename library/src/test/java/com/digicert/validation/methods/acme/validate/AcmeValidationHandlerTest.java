package com.digicert.validation.methods.acme.validate;

import com.digicert.validation.DcvContext;
import com.digicert.validation.challenges.BasicRandomValueValidator;
import com.digicert.validation.challenges.ChallengeValidationResponse;
import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.enums.AcmeType;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.AcmeValidationException;
import com.digicert.validation.exceptions.ValidationException;
import com.digicert.validation.methods.file.validate.MpicFileDetails;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.MpicFileService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsDetails;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AcmeValidationHandlerTest {

    private final String defaultDomain = "example.com";
    private final String defaultDomainWithLabel = "_acme-challenge.example.com";
    private MpicDnsService mpicDnsService;
    private MpicFileService mpicFileService;

    private AcmeValidationHandler acmeValidationHandler;
    private final String defaultRandomValue = "randomValue";
    private final String defaultAcmeThumbprint = "acme-thumbprint";
    private final String defaultFileUrl = "http://example.com/.well-known/acme-challenge/randomValue";

    @BeforeEach
    void setUp() {
        mpicDnsService = mock(MpicDnsService.class);
        mpicFileService = mock(MpicFileService.class);

        DcvContext dcvContext = mock(DcvContext.class, RETURNS_DEEP_STUBS);
        when(dcvContext.get(RandomValueValidator.class)).thenReturn(new BasicRandomValueValidator());
        when(dcvContext.get(RequestTokenValidator.class))
                .thenReturn((requestTokenData, textBody) ->
                        new ChallengeValidationResponse(Optional.of("some-request-response"), Set.of()));
        when(dcvContext.get(MpicDnsService.class)).thenReturn(mpicDnsService);
        when(dcvContext.get(MpicFileService.class)).thenReturn(mpicFileService);

        acmeValidationHandler = new AcmeValidationHandler(dcvContext);
    }

    @Test
    void testAcmeDnsValidationHandler_validate_HasMatchingRecord() throws ValidationException {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_DNS_01)
                .build();

        String calculatedDnsTxtValue = computeDnsTxtValue(defaultRandomValue + "." + defaultAcmeThumbprint);
        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.TXT, true, defaultDomainWithLabel, calculatedDnsTxtValue);
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.TXT))).thenReturn(mpicDnsDetails);

        AcmeValidationResponse response = acmeValidationHandler.validate(request);

        verify(mpicDnsService).getDnsDetails(defaultDomainWithLabel, DnsType.TXT);
        verify(mpicDnsService, never()).getDnsDetails(defaultDomain, DnsType.TXT);
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultDomainWithLabel, response.dnsRecordName());
    }

    @Test
    void testAcmeDnsValidationHandler_validate_NonMatchingRecord() throws ValidationException {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_DNS_01)
                .build();

        MpicDnsDetails mpicDnsDetails = getMpicDnsDetails(DnsType.TXT, true, defaultDomainWithLabel, "some-other-value");
        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.TXT))).thenReturn(mpicDnsDetails);
        when(mpicDnsService.getDnsDetails(eq(defaultDomain), eq(DnsType.TXT))).thenReturn(getNotFoundMpicDnsDetails(defaultDomain));

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidationHandler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
   }

    @Test
    void testAcmeDnsValidationHandler_validate_MpicDnsError() {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_DNS_01)
                .build();

        when(mpicDnsService.getDnsDetails(eq(defaultDomainWithLabel), eq(DnsType.TXT)))
                .thenReturn(getErrorMpicDnsDetails(defaultDomainWithLabel));

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidationHandler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_IO_EXCEPTION));
    }

    @Test
    void testAcmeHttpValidationHandler_validate_HasMatchingRecord() throws ValidationException {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_HTTP_01)
                .build();

        String calculatedFileContents = defaultRandomValue + "." + defaultAcmeThumbprint;
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, calculatedFileContents);
        when(mpicFileService.getMpicFileDetails(List.of(defaultFileUrl))).thenReturn(mpicFileDetails);

        AcmeValidationResponse response = acmeValidationHandler.validate(request);

        verify(mpicFileService).getMpicFileDetails(List.of(defaultFileUrl));
        assertEquals("primary-agent", response.mpicDetails().primaryAgentId());
        assertEquals(defaultFileUrl, response.fileUrl());
        assertNull(response.dnsRecordName());
    }

    @Test
    void testAcmeHttpValidationHandler_validate_NonMatchingRecord() {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_HTTP_01)
                .build();

        String calculatedFileContents = defaultRandomValue + "." + defaultAcmeThumbprint;
        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, calculatedFileContents + " some-other-value");
        when(mpicFileService.getMpicFileDetails(List.of(defaultFileUrl))).thenReturn(mpicFileDetails);

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidationHandler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
   }

    @Test
    void testAcmeHttpValidationHandler_validate_extraContent() {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_HTTP_01)
                .build();

        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, null, 200, "some-other-value");
        when(mpicFileService.getMpicFileDetails(List.of(defaultFileUrl))).thenReturn(mpicFileDetails);

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidationHandler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.RANDOM_VALUE_NOT_FOUND));
    }

    @Test
    void testAcmeHttpValidationHandler_validate_MpicFileError() {
        AcmeValidationRequest request = AcmeValidationRequest.builder()
                .domain(defaultDomain)
                .randomValue(defaultRandomValue)
                .acmeThumbprint(defaultAcmeThumbprint)
                .acmeType(AcmeType.ACME_HTTP_01)
                .build();

        MpicFileDetails mpicFileDetails = getMpicFileDetails(true, DcvError.FILE_VALIDATION_INVALID_STATUS_CODE, 400, "randomValue");
        when(mpicFileService.getMpicFileDetails(List.of(defaultFileUrl))).thenReturn(mpicFileDetails);

        AcmeValidationException exception = assertThrows(AcmeValidationException.class, () -> acmeValidationHandler.validate(request));
        assertTrue(exception.getErrors().contains(DcvError.FILE_VALIDATION_INVALID_STATUS_CODE));
    }

    private static MpicDnsDetails getMpicDnsDetails(DnsType dnsType, boolean corroborated, String domainName, String dnsValue) {
        DnsRecord dnsRecord = new DnsRecord(
                dnsType,
                domainName,
                dnsValue,
                3600,
                0,
                "");
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated));
        return new MpicDnsDetails(mpicDetails,
                domainName,
                List.of(dnsRecord),
                null);
    }

    private static MpicDnsDetails getNotFoundMpicDnsDetails(String domain) {
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", true, "secondary-2", true));
        return new MpicDnsDetails(mpicDetails,
                domain,
                List.of(),
                null);
    }

    private static MpicDnsDetails getErrorMpicDnsDetails(String domain) {
        MpicDetails mpicDetails = new MpicDetails(true,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", true, "secondary-2", true));
        return new MpicDnsDetails(mpicDetails,
                domain,
                List.of(),
                DcvError.DNS_LOOKUP_IO_EXCEPTION);
    }

    private static MpicFileDetails getMpicFileDetails(boolean corroborated, DcvError dcvError, int statusCode, String fileContents) {
        MpicDetails mpicDetails = new MpicDetails(corroborated,
                "primary-agent",
                3,
                3,
                Map.of("secondary-1", corroborated, "secondary-2", corroborated));

        return new MpicFileDetails(mpicDetails,
                "http://example.com/.well-known/pki-validation/fileauth.txt",
                fileContents,
                statusCode,
                dcvError);
    }

    @SneakyThrows
    private String computeDnsTxtValue(String keyAuthorization) {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(keyAuthorization.getBytes());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(messageDigest.digest());
    }

}