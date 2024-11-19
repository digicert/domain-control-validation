package com.digicert.validation.controller.resource.response;

import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.common.ValidationState;

import java.time.Instant;

public class ValidationStateResource {
    String domain;
    Instant prepareTime;
    DcvMethod dcvMethod;
    public ValidationState toValidationState() {
        return new ValidationState(domain, prepareTime, dcvMethod);
    }
}
