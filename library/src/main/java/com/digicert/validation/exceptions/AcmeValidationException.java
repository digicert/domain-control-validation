package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import lombok.Getter;

import java.util.Set;

@Getter
public class AcmeValidationException extends ValidationException{
    private final AcmeValidationRequest acmeValidationRequest;

    public AcmeValidationException(DcvError dcvError, AcmeValidationRequest acmeValidationRequest) {
        super(dcvError);
        this.acmeValidationRequest = acmeValidationRequest;
    }

    public AcmeValidationException(DcvError dcvError, AcmeValidationRequest acmeValidationRequest, DnssecDetails dnssecDetails) {
        super(Set.of(dcvError), dnssecDetails);
        this.acmeValidationRequest = acmeValidationRequest;
    }

}
