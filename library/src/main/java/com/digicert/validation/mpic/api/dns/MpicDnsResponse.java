package com.digicert.validation.mpic.api.dns;

import com.digicert.validation.mpic.api.MpicStatus;

import java.util.List;

public record MpicDnsResponse (PrimaryDnsResponse primaryDnsResponse,
                               List<SecondaryDnsResponse> secondaryDnsResponses,
                               MpicStatus mpicStatus,
                               long numAgentCorroborations,
                               String errorMessage) {
}
