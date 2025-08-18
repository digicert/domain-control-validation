package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import lombok.Getter;

@Getter
public class AcmeValidationException extends ValidationException{
    private final AcmeValidationRequest acmeValidationRequest;

    public AcmeValidationException(DcvError dcvError, AcmeValidationRequest acmeValidationRequest) {
        super(dcvError);
        this.acmeValidationRequest = acmeValidationRequest;
    }
}
