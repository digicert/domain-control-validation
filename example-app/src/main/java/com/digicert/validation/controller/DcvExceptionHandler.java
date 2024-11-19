package com.digicert.validation.controller;

import com.digicert.validation.exceptions.DcvBaseException;
import com.digicert.validation.exceptions.resources.DcvErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class DcvExceptionHandler {
    @ExceptionHandler(DcvBaseException.class)
    public ResponseEntity<DcvErrorResponse> handleDomainNotFoundException(DcvBaseException ex) {
        DcvErrorResponse errorResponse = new DcvErrorResponse(ex.getMessage());
        return new ResponseEntity<>(errorResponse, ex.getHttpStatusCode());
    }
}
