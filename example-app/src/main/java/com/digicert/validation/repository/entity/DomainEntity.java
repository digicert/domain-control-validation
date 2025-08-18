package com.digicert.validation.repository.entity;

import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.response.DcvRequestStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Entity
@NoArgsConstructor
@Getter
@Setter
public class DomainEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public long id;

    @Column(name = "domain_name")
    public String domainName;

    @Column(name = "account_id")
    public long accountId;

    @Column(name = "dcv_type")
    public String dcvType;

    @Column(name = "status")
    public String status;

    @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
    public List<DomainRandomValue> domainRandomValues;

    @Column(name = "validation_state")
    public String validationState;

    @Column(name = "validation_evidence", columnDefinition = "LONGTEXT")
    public String validationEvidence;

    public DomainEntity(DcvRequest request) {
        this.domainName = request.domain();
        this.accountId = request.accountId();
        this.dcvType = request.dcvRequestType().name();
        this.status = DcvRequestStatus.PENDING.name();
        this.domainRandomValues = List.of();
    }
}
