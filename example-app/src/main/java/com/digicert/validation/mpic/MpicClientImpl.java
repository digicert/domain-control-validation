package com.digicert.validation.mpic;

import com.digicert.validation.DcvManager;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.client.file.FileClient;
import com.digicert.validation.client.file.FileClientResponse;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.api.AgentStatus;
import com.digicert.validation.mpic.api.MpicStatus;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import com.digicert.validation.mpic.api.dns.MpicDnsResponse;
import com.digicert.validation.mpic.api.dns.PrimaryDnsResponse;
import com.digicert.validation.mpic.api.dns.SecondaryDnsResponse;
import com.digicert.validation.mpic.api.file.MpicFileResponse;
import com.digicert.validation.mpic.api.file.PrimaryFileResponse;
import com.digicert.validation.mpic.api.file.SecondaryFileResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.util.List;
import java.util.Set;

@Component
public class MpicClientImpl implements MpicClientInterface {

    private final ApplicationContext applicationContext;
    private DnsClient dnsClient;
    private FileClient fileClient;

    public MpicClientImpl(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public MpicDnsResponse getMpicDnsResponse(String domain, DnsType dnsType) {
        // Implementation for fetching DNS response from MPIC
        DnsData dnsData = getDnsClient().getDnsData(List.of(domain), dnsType);

        return mapToMpicDnsResponse(dnsData, dnsType, domain);
    }

    private MpicDnsResponse mapToMpicDnsResponse(DnsData dnsData, DnsType dnsType, String domain) {
        AgentStatus agentStatus = mapDnsToAgentStatus(dnsData.errors());
        List<DnsRecord> dnsRecords = mapToRecords(dnsData, dnsType);

        // Note: In a real implementation, you would have separate requests from different sources
        // For this example, we are simulating a primary response and two secondary responses with the same data.
        PrimaryDnsResponse primaryDnsResponse = new PrimaryDnsResponse("primary-agent-id", agentStatus, dnsRecords, dnsType, domain);
        SecondaryDnsResponse secondaryDnsResponse1 = new SecondaryDnsResponse("secondary-agent-id-1", agentStatus, true, dnsRecords);
        SecondaryDnsResponse secondaryDnsResponse2 = new SecondaryDnsResponse("secondary-agent-id-2", agentStatus, true, dnsRecords);

        return new MpicDnsResponse(primaryDnsResponse,
                List.of(secondaryDnsResponse1, secondaryDnsResponse2),
                MpicStatus.CORROBORATED,
                2L,
                null);
    }

    private List<DnsRecord> mapToRecords(DnsData dnsData, DnsType dnsType) {
        if (dnsData == null || dnsData.records() == null || dnsData.records().isEmpty()) {
            return List.of();
        }

        return dnsData.records().stream()
                .map(this::mapRecordToDnsRecord)
                .toList();
    }

    private DnsRecord mapRecordToDnsRecord(Record recordValue) {
        DnsRecord.DnsRecordBuilder dnsRecordBuilder = DnsRecord.builder();

        switch (recordValue) {
            case TXTRecord txtRecord -> dnsRecordBuilder.value(txtRecord.rdataToString());
            case CNAMERecord cnameRecord -> dnsRecordBuilder.value(cnameRecord.getTarget().toString());
            case ARecord aRecord -> dnsRecordBuilder.value(aRecord.getAddress().toString());
            case MXRecord mxRecord -> dnsRecordBuilder.value(mxRecord.getTarget().toString());
            case CAARecord caaRecord -> {
                dnsRecordBuilder.value(caaRecord.getValue());
                dnsRecordBuilder.flag(caaRecord.getFlags());
                dnsRecordBuilder.tag(caaRecord.getTag());
            }
            case DSRecord dsRecord -> dnsRecordBuilder.value(dsRecord.toString());
            case RRSIGRecord rrsigRecord -> dnsRecordBuilder.value(rrsigRecord.toString());
            default -> throw new IllegalStateException("Unexpected value: " + recordValue);
        }

        dnsRecordBuilder.name(recordValue.getName().toString());
        dnsRecordBuilder.dnsType(DnsType.fromInt(recordValue.getType()));
        dnsRecordBuilder.ttl(recordValue.getTTL());

        return dnsRecordBuilder.build();
    }

    private AgentStatus mapDnsToAgentStatus(Set<DcvError> errors) {
        if (errors == null || errors.isEmpty()) {
            return AgentStatus.DNS_LOOKUP_SUCCESS;
        }

        return switch (errors.stream().findFirst().orElseThrow()) {
            case DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION -> AgentStatus.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION;
            case DNS_LOOKUP_TEXT_PARSE_EXCEPTION -> AgentStatus.DNS_LOOKUP_TEXT_PARSE_EXCEPTION;
            default -> AgentStatus.DNS_LOOKUP_RECORD_NOT_FOUND;
        };
    }

    private AgentStatus mapFileToAgentStatus(DcvError error) {
        if (error == null) {
            return AgentStatus.FILE_SUCCESS;
        }

        return switch (error) {
            case FILE_VALIDATION_CLIENT_ERROR -> AgentStatus.FILE_CLIENT_ERROR;
            case FILE_VALIDATION_INVALID_CONTENT -> AgentStatus.FILE_BAD_RESPONSE;

            default -> AgentStatus.FILE_SERVER_ERROR;
        };
    }

    @Override
    public MpicFileResponse getMpicFileResponse(String fileUrl) {
        FileClientResponse fileClientResponse = getFileClient().executeRequest(fileUrl);

        return mapToMpicFileResponse(fileClientResponse, fileUrl);
    }

    private MpicFileResponse mapToMpicFileResponse(FileClientResponse fileClientResponse, String fileUrl) {
        AgentStatus agentStatus = mapFileToAgentStatus(fileClientResponse.getDcvError());

        int statusCode = fileClientResponse.getStatusCode();
        String fileContent = fileClientResponse.getFileContent();
        String foundUrl = fileClientResponse.getFileUrl();

        // Note: In a real implementation, you would have separate requests from different sources
        // For this example, we are simulating a primary response and two secondary responses with the same data.
        PrimaryFileResponse primaryFileResponse = new PrimaryFileResponse("primary-agent-id", statusCode, agentStatus, fileUrl, foundUrl, fileContent);
        SecondaryFileResponse secondaryFileResponse1 = new SecondaryFileResponse("secondary-agent-id-1", statusCode, agentStatus, true);
        SecondaryFileResponse secondaryFileResponse2 = new SecondaryFileResponse("secondary-agent-id-2", statusCode, agentStatus, true);

        return new MpicFileResponse(primaryFileResponse,
                List.of(secondaryFileResponse1, secondaryFileResponse2),
                MpicStatus.CORROBORATED,
                2L,
                null);
    }

    private DnsClient getDnsClient() {
        if (dnsClient == null) {
            DcvManager dcvManager = applicationContext.getBean(DcvManager.class);
            dnsClient = dcvManager.getDnsClient();
        }
        return dnsClient;
    }

    public FileClient getFileClient() {
        if (fileClient == null) {
            DcvManager dcvManager = applicationContext.getBean(DcvManager.class);
            fileClient = dcvManager.getFileClient();
        }
        return fileClient;
    }
}
