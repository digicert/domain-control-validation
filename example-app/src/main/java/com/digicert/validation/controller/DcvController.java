package com.digicert.validation.controller;

import com.digicert.validation.controller.resource.request.DcvRequest;
import com.digicert.validation.controller.resource.response.DomainResource;
import com.digicert.validation.controller.resource.request.ValidateRequest;
import com.digicert.validation.exceptions.DcvBaseException;
import com.digicert.validation.service.DcvService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
public class DcvController {

    private final DcvService dcvService;

    @Autowired
    public DcvController(DcvService dcvService) {
        this.dcvService = dcvService;
    }

    @PostMapping("/domains")
    @ResponseStatus(HttpStatus.CREATED)
    public DomainResource submitDomain(@RequestBody DcvRequest dcvRequest) throws DcvBaseException {
        return dcvService.submitDomain(dcvRequest);
    }

    @GetMapping("/domains/{domainId}")
    @ResponseStatus(HttpStatus.OK)
    public DomainResource getDomains(@PathVariable("domainId") Long domainId) throws DcvBaseException{
        return new DomainResource(dcvService.getDomainEntity(domainId));
    }

    @PutMapping("/domains/{domainId}")
    public void validateDomain(@PathVariable("domainId") Long domainId,
                             @RequestBody ValidateRequest dcvRequest) throws DcvBaseException {
        dcvService.validateDomain(domainId, dcvRequest);
    }

    @PostMapping("/accounts/{accountId}/tokens")
    @ResponseStatus(HttpStatus.CREATED)
    public void createAccountToken(@PathVariable("accountId") long accountId, @RequestParam("tokenKey") String tokenKey) {
        dcvService.createTokenForAccount(accountId, tokenKey);
    }

}
