# example-app Workflow Examples
There are two examples of workflows below, one for the EMAIL_CONSTRUCTED method and one for the DNS_TXT method.
The EMAIL_CONSTRUCTED method is a simple email-based method that sends emails to the pre-constructed emails
(admin, administrator, hostmaster, postmaster, and webmaster) with a random value. The DNS_TXT method is a more complex
method that requires the user to add a TXT record to their DNS server.

## example-app Flow (EMAIL_CONSTRUCTED Method)
Assuming we're following the happy path, the example-app flow (using the DNS method) is as follows:
1. User Sends 'Submit Domain' Request to API<br>
   cURL request made to submit domain:
```
curl --location 'http://localhost:8080/domains' \
--header 'Content-Type: application/json' \
--data '{
    "domain":"digicert.com",
    "accountId":1,
    "dcvRequestType":"EMAIL_CONSTRUCTED"
}'
```
-- API response:
```
{
    "domainResource": {
        "id": 1,
        "domainName": "digicert.com",
        "accountId": 1,
        "dcvType": "EMAIL_CONSTRUCTED",
        "status": "PENDING",
    }
}
```
2. DcvController Receives Request and Calls DcvService<br>
   (Snippet from DcvController.java:)
```
@PostMapping("/domains")
    @ResponseStatus(HttpStatus.CREATED)
    public DomainResource submitDomain(@RequestBody DcvRequest dcvRequest) throws DcvBaseException {
        return dcvService.submitDomain(dcvRequest);
    }
```
3. DcvService Creates the domainId and Prepares for Validation<br>
   (Both snippets are from the DcvService class)
```   
public DomainResource submitDomain(DcvRequest dcvRequest) throws DcvBaseException {
        // ... (dcvRequestType and error handling logic)
        
        try {
            switch (dcvRequest.dcvRequestType()) {
                case DNS_TXT, DNS_CNAME, DNS_TXT_TOKEN -> createdEntity = submitDnsDomain(dcvRequest);
                case EMAIL_CONSTRUCTED, EMAIL_WHOIS, EMAIL_DNS_TXT -> createdEntity = submitEmailDomain(dcvRequest);
                case FILE_VALIDATION, FILE_VALIDATION_TOKEN -> createdEntity = submitFileDomain(dcvRequest);
            }
        
        // ... (error handling logic)
        
        return new DomainResource(createdEntity);
    }
```
```   
private DomainEntity submitEmailDomain(DcvRequest dcvRequest) throws DcvBaseException, DcvException {
        // .. (mapping and preparation logic)
        
        try {
            preparationResponse = dcvManager.getEmailValidator().prepare(emailPreparation);
        } 
           // ... (error handling logic)
        }
        // Send the email
        log.info("Email sent to: {}", preparationResponse.emailWithRandomValue());

        // Save the validation state to the database
        return saveEmailValidationState(dcvRequest, preparationResponse);
    }
```
4. Domain Info Returned, Request to Validate is Made<br>
   Once the API returns the domain info, the user can utilize the random value emailed to the respective email address to validate the domain (cURL request made to validate domain):
```
curl --location --request PUT 'http://localhost:8080/domains/1' \
--header 'Content-Type: application/json' \
--data-raw '{
    "domain":"digicert.com",
    "randomValue": "{{randomValue}}",
    "emailAddress": "administrator@digicert.com",
    "dcvRequestType":"EMAIL_CONSTRUCTED"
}'
```
5. Validate Domain Request<br>
   Once the DcvController receives a request to validate, it calls the DcvService (code snippet from DcvController):
```
@PutMapping("/domains/{domainId}")
public void validateDomain(@PathVariable("domainId") Long domainId,
@RequestBody ValidateRequest dcvRequest) throws DcvBaseException {
dcvService.validateDomain(domainId, dcvRequest);
}
```
6. DcvService Sets Up Validation<br>
   The DcvService will call the validateEmail method to validate the domain via randomValue (code snippet from DcvService):
```
private void validateEmailDomain(ValidationState validationState, ValidateRequest validateRequest) throws DcvBaseException {
        EmailSource emailSource = mapToEmailSource(validateRequest.dcvRequestType);
        EmailValidationRequest emailVerification = EmailValidationRequest.builder()
                // ... (builder logic)

        try {
            dcvManager.getEmailValidator().validate(emailVerification);
        // ... (error handling logic)
    }
```
7. EmailValidator Validates the Request<br>
   The EmailValidator class is stepped through and initializes the email providers using the following steps:<br>
   a. Appropriate email provider is found and random values are generated<br>
   b. A ValidationState is created and an EmailPreparationResponse containing the domain, email, source, emails with random values, and validation state is returned<br>
   c. The random value is validated against the preparation time using the RandomValueVerifier<br>
   d. DomainValidationEvidence object containing domain, email address, random value, DCV method, and validation date is created and returned
   

## example-app Flow (DNS-TXT Method)
Assuming we're following the happy path, the example-app flow (using the DNS method) is as follows:
1. User Sends 'Submit Domain' Request to API<br>
   cURL request made to submit domain:
```
curl --location 'http://localhost:8080/domains' \
--header 'Content-Type: application/json' \
--data '{
    "domain":"digicert.com",
    "accountId":1,
    "dcvRequestType":"DNS_TXT"
}'
```
-- API response:
```
{
    "domainResource": {
        "id": 1,
        "domainName": "digicert.com",
        "accountId": 1,
        "dcvType": "DNS_TXT",
        "status": "PENDING",
        "randomValueDetails": [
            {
                "randomValue": "{{randomValue}}",
                "email": null
            }
        ]
    }
}
```
2. DcvController Receives Request and Calls DcvService
```
From DcvController.java:

@PostMapping("/domains")
    @ResponseStatus(HttpStatus.CREATED)
    public DomainResource submitDomain(@RequestBody DcvRequest dcvRequest) throws DcvBaseException {
        return dcvService.submitDomain(dcvRequest);
    }
```
3. DcvService Creates the domainId and Prepares for Validation<br>
   (Both snippets are from the DcvService class)
```
public DomainResource submitDomain(DcvRequest dcvRequest) throws DcvBaseException {
        // ... (dcvRequestType and error handling logic)

        return new DomainResource(createdEntity);
    }
```
```
private DomainEntity submitDnsDomain(DcvRequest dcvRequest) throws DcvBaseException {
        // ... (mapping and preparation logic)
        
        try {
            DnsPreparationResponse prepare = dcvManager.getDnsValidator().prepare(dnsPreparation);

            // Save the validation state to the database
            return saveDnsValidationState(dcvRequest, prepare);
        // ... (error handling logic)
        }
    }
```
4. Domain Info Returned, Request to Validate is Made<br>
   Once the API returns the domain info, the user can utilize the returned ID, random value, and email to validate the domain (cURL request made to validate domain):
```
curl --location --request PUT 'http://localhost:8080/domains/1' \
--header 'Content-Type: application/json' \
--data-raw '{
    "domain":"digicert.com",
    "randomValue": "{{randomValue}}",
    "dcvRequestType":"DNS_TXT"
}'
```

5. Validate Domain Request<br>
   The DcvController receives a request to validate and calls the DcvService (code snippet from DcvController):
```
@PutMapping("/domains/{domainId}")
public void validateDomain(@PathVariable("domainId") Long domainId,
@RequestBody ValidateRequest dcvRequest) throws DcvBaseException {
dcvService.validateDomain(domainId, dcvRequest);
}
```
6. DcvService Sets Up Validation<br>
   The DcvService will call the validateDnsDomain method to validate the domain via RANDOM_VALUE or DNS_TXT_TOKEN:
```
private void validateDnsDomain(long accountId, ValidationState validationState, ValidateRequest validateRequest)
            throws DcvBaseException {

        DnsType dnsType = mapToDnsType(validateRequest.dcvRequestType);
        DnsValidationRequest.DnsValidationRequestBuilder requestBuilder = DnsValidationRequest.builder()
                // ... (builder logic)

        // ... (set the token key if it is a DNS_TXT_TOKEN request)

        DnsValidationRequest dnsValidationRequest = requestBuilder.build();

        try {
            dcvManager.getDnsValidator().validate(dnsValidationRequest);
        // ... (error handling logic)
    }
```
7. DnsValidator Verifies the Request<br>
   The DnsValidator verifies the request using the verifyDnsValidationRequest method:
```
private void verifyDnsValidationRequest(DnsValidationRequest request) throws DcvException {
        // ... (verification logic)
    }
```
8. DnsValidator Called to Validate the Request<br>
   If the domain is valid, the DnsValidator will be called to validate:
```
public DomainValidationEvidence validate(DnsValidationRequest dnsValidationRequest) throws DcvException {
        // ... (processing logic and random value verification)
        
        DnsValidationResponse dnsValidationResponse = dnsValidationHandler.validate(dnsValidationRequest);

        if (dnsValidationResponse.isValid()) {
            log.info("event_id={} domain={}", LogEvents.DNS_VALIDATION_SUCCESSFUL, dnsValidationRequest.getDomain());
            return createDomainValidationEvidence(dnsValidationRequest, dnsValidationResponse);
        }
    }
```
9. DomainValidationEvidence is Created<br>
    If all checks pass, the DomainValidationEvidence is created:
```
private DomainValidationEvidence createDomainValidationEvidence(DnsValidationRequest dnsValidationRequest,
                                                                    DnsValidationResponse dnsValidationResponse) {
        return DomainValidationEvidence.builder()
                // ... (builder logic)
    }
```
10. Log Successful Validation<br>
    If the domain is valid, successful validation message is then logged with domain name (code snippet from the DnsValidator class).
    '200 OK' response code is expected. Otherwise, error is returned.
```
if (dnsValidationResponse.isValid()) {
            log.info("event_id={} domain={}", LogEvents.DNS_VALIDATION_SUCCESSFUL, dnsValidationRequest.getDomain());
            return createDomainValidationEvidence(dnsValidationRequest, dnsValidationResponse);
```