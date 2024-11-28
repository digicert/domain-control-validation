![Build and Test](https://github.com/digicert/domain-control-validation/actions/workflows/beta-build-deploy.yml/badge.svg)
![CodeQL](https://github.com/digicert/domain-control-validation/actions/workflows/codeql.yml/badge.svg)

Domain Control Validation
====================
This library represents DigiCert's domain control validation (DCV) process. This is to satisfy the requirements specified in the
[CAB Forum baseline requirements](https://github.com/cabforum/servercert/blob/main/docs/BR.md#3224-validation-of-domain-authorization-or-control)
to validate that an applicant has ownership or control over a domain. The BR documents multiple methods by which such control
can be demonstrated. This initial version of the library is available for review. 

DigiCert is open-sourcing this code to improve transparency and security around Domain Control Validation. We hope that others also will find this valuable for their DCV efforts. 

For each method, this library has a preparation step and a validation step. The preparation step supplies information that is
necessary for setting up the DCV, including generating a value that can be used as the required random value. The validation
step performs the DCV (where possible) and validates that the necessary information has been received.

NOTE: For a high-level overview of the DCV process, as well as the details information on how request and response
objects are used, please refer to the [README-details.md](README-details.md) file.

Supported Methods
-----------------

### [Email, Fax, SMS, or Postal Mail to Domain Contact](https://github.com/cabforum/servercert/blob/main/docs/BR.md#32242-email-fax-sms-or-postal-mail-to-domain-contact)
* The prepare step obtains contact information for the [domain contact](https://github.com/cabforum/servercert/blob/main/docs/BR.md#161-definitions).
  The library does not facilitate sending the random value to the applicant.
* This library does not facilitate receiving the random value from the applicant. The validation step can only confirm the appropriate
  data has been collected.

### [Constructed Email to Domain Contact](https://github.com/cabforum/servercert/blob/main/docs/BR.md#32244-constructed-email-to-domain-contact)
* The prepare step generates the possible email addresses to which the random value could be sent. The library does not facilitate
  sending the random value to the applicant.
* This library does not facilitate receiving the random value from the applicant. The validation step can only confirm the appropriate
  data has been collected.

### [DNS Change](https://github.com/cabforum/servercert/blob/main/docs/BR.md#32247-dns-change)
* The prepare step only returns a random value that can be used and the domains that could be used to validate the given FQDN.
* The validate step will call the DNS servers and obtain the specified record type for the specified domain. It will also check
  with the configurable domain label prefixed. If the random value is found in the record, the DCV can be considered complete.

### [Email to DNS TXT Contact](https://github.com/cabforum/servercert/blob/main/docs/BR.md#322414-email-to-dns-txt-contact)
* The prepare step obtains the email address of the [DNS TXT record email contact](https://github.com/cabforum/servercert/blob/main/docs/BR.md#a21-dns-txt-record-email-contact).
  The library does not facilitate sending the random value to the applicant.
* This library does not facilitate receiving the random value from the applicant. The validation step can only confirm the appropriate
  data has been collected.

### [Agreed-Upon Change to Website v2](https://github.com/cabforum/servercert/blob/main/docs/BR.md#322418-agreed-upon-change-to-website-v2)
* The prepare step returns a random value that can be used and the file url that will be checked. If a file name is provided the
  file url will use it, otherwise it will use the configurable default file name.
* The validate step will make http calls (http on port 80 and https on port 443) to the domain at the provided file name (or the
  configurable default). If the random value is found at the location, the DCV can be considered complete.

API Documentation
-----------------
The domain-control-validation library provides a set of APIs to perform domain control validation (DCV) as per the CAB Forum baseline requirements. Below are examples of how to use the library in your project.  

### Adding the Dependency

First, add the domain-control-validation library as a dependency in your pom.xml:

```xml
<dependency>
    <groupId>com.digicert.validation</groupId>
    <artifactId>domain-control-validation-parent</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

### Using the Library
Please refer to the [README-details.md](README-details.md) file for details on how to integrate and use the library


## Java Docs
The JavaDocs for the example-app can be generated via maven java-doc plugin.
```mvn javadoc:javadoc``` The generated JavaDocs can be found in the `target/reports/apidocs` directory.

The root file of the JavaDocs is can be viewed in a browser via:
### example-app
`file:///<path-to-repo>/example-app/target/reports/apidocs/index.html`

### domain-control-validation library
`file:///<path-to-repo>/library/target/reports/apidocs/index.html`

Example-App
-----------
The example-app module is a reference implementation of the domain-control-validation library. This can be used as an example of how to call the API is domain-control-validation. This example-app includes a REST API implementation that uses the domain-control-validation and full flow integration tests of the BRs implemented in domain-control validation.
See the [example-app README](example-app/README.md) for more information.

Domain-Control-Validation
-------------------------
The library (domain-control-validation) module is the core of the domain-control-validation library. This module contains 
the implementation of the DCV methods and the API to interact with them. This module also contains the unit tests for the library.
See the [library README](library/README.md) for more information.

Building
--------
run `mvn clean install` from the root of the repository to build the library and example-app.

Running the example application
---------------------------------
Instructions for running the example application

Unit Testing
------------
run `mvn clean test` from the root of the repository to run the unit tests and then integration tests.


Acceptance Testing
------------------
How to run the acceptance tests

### Running Acceptance Tests Locally
This will be the most basic way to run the acceptance tests


### Debugging Acceptance Tests in Intellij
How to run the acceptance tests in a way that allows for debugging the tests. We might not need to include this section in the final version of the readme

### Guava Attribution 
InternetDomainName has changed DCVDomainName
Copyright (C) 2009 The Guava Authors

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0