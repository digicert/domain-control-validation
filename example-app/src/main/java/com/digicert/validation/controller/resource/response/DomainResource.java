package com.digicert.validation.controller.resource.response;

import com.digicert.validation.controller.resource.request.DcvRequestType;
import com.digicert.validation.repository.entity.DomainEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class DomainResource {
    private long id;
    private String domainName;
    private long accountId;
    private DcvRequestType dcvType;
    private DcvRequestStatus status;
    private List<DomainRandomValueDetails> randomValueDetails = new ArrayList<>();

    public DomainResource(DomainEntity domain) {
        this.id = domain.getId();
        this.domainName = domain.getDomainName();
        this.accountId = domain.getAccountId();
        this.dcvType = DcvRequestType.valueOf(domain.getDcvType());
        this.status = DcvRequestStatus.valueOf(domain.getStatus());
        randomValueDetails = domain.getDomainRandomValues().stream()
                .map(DomainRandomValueDetails::new)
                .toList();
    }
}
