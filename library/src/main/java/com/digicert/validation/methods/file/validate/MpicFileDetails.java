package com.digicert.validation.methods.file.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.mpic.MpicDetails;


public record MpicFileDetails(MpicDetails mpicDetails,
                              String fileUrl,
                              String fileContent,
                              int statusCode,
                              DcvError dcvError) { }
