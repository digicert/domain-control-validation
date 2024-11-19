package com.digicert.validation.controller.resource.response;

import com.digicert.validation.repository.entity.DomainRandomValue;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class DomainRandomValueDetails {
    private String randomValue;
    private String email;

    public DomainRandomValueDetails(DomainRandomValue domainRandomValue) {
        this.randomValue = domainRandomValue.randomValue;
        this.email = domainRandomValue.email;
    }
}
