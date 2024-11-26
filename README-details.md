Domain Control Validation - Details
========================================
This file aims to provide detailed request and response objects for the Domain Control Validation (DCV) process. 
This does not include the actual implementation of the DCV process, but rather the objects used to perform the validation.

Please refer to the Javadocs for detailed information on the classes and methods available in the library.

Please note: There are certain classes and methods that are included in the example application (example-app module)
repository that are not included in the actual implementation of the DCV process from the DCV Manager. These methods and
classes are used internally by example application and are not required for the DCV process to function properly.

## Workflow Diagram
Below is a simplified diagram illustrating the workflow of the DCV process:

1. **Preparation Request**: Submit a preparation request to prepare for validation
2. **Preparation Response**: Receive a preparation response with details for validation
3. **Validation Request**: Submit a validation request (DNS, Email, or File Validation)
4. **Validation Response**: Perform the validation and receive the validation response

```plaintext
 +----------------------+       +----------------------+      
 | Preparation Request  | ----> | Preparation Response |
 | (DNS/Email/File)     |       |                      |      
 +----------------------+       +----------------------+      

----> Allow for user to place random value / token in appropriate location

 +----------------------+       +----------------------------+
 |  Validation Request  | ----> |    Validation Response     |
 |                      |       | (DomainValidationEvidence) |
 +----------------------+       +----------------------------+ 
```

## Integrating the library into your application

The library provides a 'DcvManager' class that can be used to perform DCV. The 'DcvManager' class has two main methods: 'prepare' and 'validate'. 
The 'prepare' method is used to prepare the DCV process, and the 'validate' method is used to validate the DCV process.

First, create a 'DcvConfiguration' object with the desired configuration options.

```java
import com.digicert.domaincontrolvalidation.DcvConfiguration;

DcvConfiguration configuration = DcvConfiguration().Builder()
        .dnsTimeout(2000)
        .dnsRetries(3)
        .build();
```

Next create a 'DcvManager' instance and set the configuration using the DcvManager.Builder class:

```java
import com.digicert.domaincontrolvalidation.DcvManager;

DcvManager dcvManager = DcvManager().Builder()
    .withDcvConfiguration(configuration)
    .build();
```

Depending on the type of validation you are looking to do, you will need to retrieve the appropriate validator from the 'DcvManager' instance. For example, to perform DNS validation, you will need to retrieve the DNS validator. To perform email validation, you will need to retrieve the email validator. Or to perform file validation, you will need to retrieve the file validation validator.

```java
import com.digicert.domaincontrolvalidation.DnsValidator;
import com.digicert.domaincontrolvalidation.EmailValidator;
import com.digicert.domaincontrolvalidation.FileValidator;

DnsValidator dnsValidator = dcvManager.getDnsValidator();
EmailValidator emailValidator = dcvManager.getEmailValidator();
FileValidator fileValidator = dcvManager.getFileValidator();
```

### Use of the DnsValidator
For our example we will create a 'DnsPreparation' object with the required parameters and call the 'prepare' method to prepare the DCV process:

```java
import com.digicert.domaincontrolvalidation.DnsPreparation;

DnsPreparation dnsPreparation = new DnsPreparation("example.com", DnsType.TXT, ChallengeType.RANDOM_VALUE);

DnsPreparationResponse prepare = dnsValidator.prepare(dnsPreparation);
```

The 'prepare' method will return a 'DnsPreparationResponse' object with the necessary information to validate the DCV process. You can then use this information to validate the DCV process using the 'validate' method.

Create a 'DnsValidationRequest' object with the required parameters using the Builder class. Then call the 'validate' method to validate the DCV process:

```java
import com.digicert.domaincontrolvalidation.DnsValidationRequest;

DnsValidationRequest dnsValidationRequest = DnsValidationRequest().Builder()
        .domain(prepare.getDomain())
        .dnsType(prepare.getDnsType())
        .challengeType(prepare.getSecretType())
        .randomValue(prepare.getRandomValue()) // only one of randomValue or tokenValue / tokenKey should be provided
//        .tokenKey("tokenKey")
//        .tokenValue("tokenValue")
        .validationState(prepare.getValidationState())
        .build();

DomainValidationEvidence evidence = dnsValidator.validate(dnsValidationRequest);
```

The 'validate' method will return a 'DomainValidationEvidence' object with the results of the DCV process. You can use this object to determine if the DCV process was successful.

## Detailed Request and Response Objects
### BR 3.2.2.4.18 - Agreed-Upon Change to Website (File Change) 
#### FilePreparationRequest
The `FilePreparationRequest` is used to prepare the file validation process

| Field           | Type             | Description                                 |
|-----------------|------------------|---------------------------------------------|
| domain          | String           | The domain name to validate.                |
| challengeType   | ChallengeType    | The secret type to use for the DCV process. |

#### FilePreparationResponse
The `FilePreparationResponse` object is returned by the `FileValidator` after the `prepare` method is called. This preparation response object contains the necessary information to validate the DCV process, as well as the following fields:

| Field           | Type            | Description                               |
|-----------------|-----------------|-------------------------------------------|
| domain          | String          | The domain name that was validated.       |
| challengeType   | ChallengeType      | The secret type used for the DCV process. |
| randomValue     | String          | A random value used for validation.       |
| validationState | ValidationState | The state of the validation process.      |

NOTE: The validationState object returned here will be used in the subsequent validation request

##### Example
```java
FilePreparationRequest filePreparationRequest = new FilePreparationRequest("example.com", ChallengeType.RANDOM_VALUE);
FilePreparationResponse response = fileValidator.prepare(filePreparationRequest);
```

#### FileValidation Request
The `FileValidationRequest` object is likewise used to provide the necessary information to the `FileValidator` to perform the DCV process, and contains the following fields:

| Field           | Type                | Description                                 |
|-----------------|---------------------|---------------------------------------------|
| domain          | String              | The domain name to validate.                |
| randomValue     | String              | A random value used for validation.         |
| filename        | String	             | The filename used for validation.           |
| tokenKey        | String              | A token key used for validation.            |
| tokenValue      | String              | A token value used for validation.          |
| challengeType   | ChallengeType       | The secret type to use for the DCV process. |
| validationState | ValidationState     | The state of the validation process.        |

NOTES: 
- Either randomValue or tokenValue should be provided based on the challengeType
- Filename can be null if the default filename (found in the configuration) will be used
- The validationState object used here is what was returned on the preparation response

#### FileValidation Response
##### DomainValidationEvidence
The `DomainValidationEvidence` object is returned by the `FileValidator` after the `validate` method is called. 
This validation response object contains the result of the DCV process, as well as the following fields:

##### DomainValidationEvidence Fields (used in each validation method, but not all fields are used in each method):

| Field          | Type      | Description                                                                     |
|----------------|-----------|---------------------------------------------------------------------------------|
| domain         | String    | The domain name that was validated. Used in File, DNS, Email validation.        |
| dcvMethod      | DcvMethod | The URL of the file used for validation. Used in File, DNS, Email validation.   |
| BrVersion      | String    | Version of baseline requirements. Used for each method.                         |
| validationDate | Instant   | The date of validation. Used in Email and DNS validation.                       |
| emailAddress   | String    | The email address used for validation. Used in File and Email validation.       |
| fileUrl        | String    | The URL of the file used for validation. Used in File validation.               |
| dnsType        | DnsType   | The DNS record type used for validation. Used in DNS validation.                |
| dnsServer      | String    | The DNS server used for validation. Used in DNS validation.                     |
| dnsRecordName  | String    | The DNS record name used for validation. Used in DNS validation.                |
| foundToken     | String    | The token found in the file. Used in File and DNS validation.                   |
| randomValue    | String    | The random value used for validation. Used in File, DNS, and Email validation.  |


#### Example of the File Validation request / response
```java
FileValidationRequest fileValidationRequest = FileValidationRequest.builder()
        .domain(prepare.getDomain())
        .randomValue(prepare.getRandomValue())
        .challengeType(ChallengeType.RANDOM_VALUE)
        .validationState(prepare.getValidationState())
        .build();

DomainValidationEvidence evidence = fileValidator.validate(request);
```

### BR 3.2.2.4.7 - DNS Change
#### DnsPreparation Request and Response
The `DnsPreparationRequest` object is used to prepare the DNS validation process. This request object is built using the `DnsPreparationRequest.Builder` class, and contains the following fields:

| Field           | Type             | Description                                     |
|-----------------|------------------|-------------------------------------------------|
| domain          | String           | The domain name to validate.                    |
| dnsType         | DnsType          | The DNS record type to use for the DCV process. |
| challengeType   | ChallengeType    | The secret type to use for the DCV process.     |

The `DnsPreparationResponse` object is returned by the `DnsValidator` after the `prepare` method is called. This preparation response object contains the necessary information to validate the DCV process, as well as the following fields:

| Field           | Type            | Description                                                |
|-----------------|-----------------|------------------------------------------------------------|
| dnsType         | DnsType         | The DNS record type to use for the DCV process.            |
| domain          | String          | The domain name to validate.                               |
| allowedFqdns    | List<String>    | Allowed domains and sub-domains based on requested domain. |
| validationState | ValidationState | The validation state of the DCV process.                   |

NOTE: The validationState object returned here will be used in the subsequent validation request

##### Example
```java
DnsPreparation dnsPreparation = new DnsPreparation("example.com", DnsType.TXT, ChallengeType.RANDOM_VALUE);
DnsPreparationResponse dnsPreparationResponse = dnsValidator.prepare(dnsPreparation);
```

#### DnsValidation Request and Response
The `DnsValidationRequest` object is used to provide the necessary information to the `DnsValidator` to perform the DCV process, and contains the following fields:

| Field            | Type             | Description                                      |
|------------------|------------------|--------------------------------------------------|
| domain           | String           | The domain name to validate.                     |
| randomValue      | String           | A random value used for validation.              |
| tokenValue       | String           | A token value used for validation.               |
| dnsType          | DnsType          | The DNS record type to use for the DCV process.  |
| challengeType    | ChallengeType    | The secret type to use for the DCV process.      |
| validationState  | ValidationState  | The state of the validation process.             |

NOTES:
- Either randomValue or tokenValue should be provided based on the challengeType
- The validationState object used here is what was returned on the preparation response

#### DnsValidationResponse
The `DnsValidationResponse` object is returned by the `DnsValidator` after the `validate` method is called. This validation response object contains the result of the DCV process, as well as the following fields:
##### DomainValidationEvidence (As shown above, lines 82-94)

##### Example from DnsValidator
```java
DnsValidationRequest request = DnsValidationRequest.builder()
        .domain(prepare.getDomain())
        .randomValue(prepare.getRandomValue())
        .dnsType(DnsType.CNAME)
        .challengeType(ChallengeType.RANDOM_VALUE)
        .validationState(prepare.getValidationState())
        .build();

DnsValidationResponse response = dnsValidationHandler.validate(request);
```


### BR: 3.2.2.4.2 / 3.2.2.4.4 / 3.2.2.4.14 - Email to Domain Contact / Constructed Email / DNS TXT Contact
#### EmailPreparationRequest - Email Preparation
The `EmailPreparationRequest` object is used to prepare the email validation process. This request object is built using the `EmailPreparationRequest.Builder` class, and contains the following fields:

| Field           | Type             | Description                             |
|-----------------|------------------|-----------------------------------------|
| domain          | String           | The domain name to validate.            |
| emailSource     | EmailSource      | The source of the email addresses.      |

The `EmailPreparationResponse` object is returned by the `EmailValidator` after the `prepare` method is called. This preparation response object contains the necessary information to validate the DCV process, as well as the following fields:

| Field                | Type                          | Description                                           |
|----------------------|-------------------------------|-------------------------------------------------------|
| domain               | String                        | The domain associated with the email preparation.     |
| emailSource          | EmailSource                   | The source of the email.                              |
| emailWithRandomValue | List<EmailWithRandomValue>    | A list of emails with their associated random values. |
| validationState      | ValidationState               | The validation state of the email preparation.        |

##### Example from EmailValidator
```java
EmailPreparation emailPreparation = new EmailPreparation("example.com", EmailSource.CONSTRUCTED);
EmailPreparationResponse emailPreparationResponse = emailValidator.prepare(emailPreparation);
```


#### EmailValidation Request and Response
The `EmailValidationRequest` object is used to provide the necessary information to the `EmailValidator` to perform the DCV process, and contains the following fields:

| Field           | Type             | Description                             |
|-----------------|------------------|-----------------------------------------|
| domain          | String           | The domain name to validate.            |
| emailSource     | EmailSource      | The source of the email addresses.      |
| emailAddress    | String           | The email address used for validation.  |
| randomValue     | String           | A random value used for validation.     |
| validationState | ValidationState  | The state of the validation process.    |

NOTES:
- randomValue should be provided
- The validationState object used here is what was returned on the preparation response

##### EmailValidationResponse
The `EmailValidationResponse` object is returned by the `EmailValidator` after the `validate` method is called. This validation response object contains the result of the DCV process, as well as the following fields:
##### DomainValidationEvidence (As shown above, lines 82-94)

##### Example of the Email validation request / response
```java
EmailValidationRequest emailValidationRequest = EmailValidationRequest.builder()
        .domain("example.com")
        .emailSource(EmailSource.CONSTRUCTED)
        .emailAddress("webmaster@example.com")
        .randomValue("some-random-value")
        .validationState(prepare.getValidationState())
        .build();
```