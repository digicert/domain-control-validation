# ACME Development Guide

Quick developer guide for the ACME implementation

## How It Works

## 1. ACME DNS-01 Flow

### Setting Up an Account for ACME Validation

To configure an account for ACME validation, follow these steps:

1. **Set ACME Thumbprint**  
    Use the `/accounts/{id}/tokens` endpoint to set the ACME thumbprint for the account. This thumbprint is required for ACME validation.

    ### Setting ACME Thumbprint via API

    To set the ACME thumbprint for account `1234`, use the following curl command:

    **For testing, use this pre-generated thumbprint:**

    ```bash
    curl -X POST "http://localhost:8080/accounts/1234/tokens?tokenKey=NvqJa7v_nqGJGnbD_x4dAY4SgA9FCXBNmz_Rm34S6jM" \
        -H "Content-Type: application/json"
    ```

    **For production, generate your own ACME account key thumbprint using your ACME client library.**

    Replace `YOUR_THUMBPRINT` with the actual thumbprint value.

    ```bash
    curl -X POST "localhost:8080/accounts/{accountId}/tokens?tokenKey={thumbprint}"
    ```

    Replace `{accountId}` with the ID of the account and `{thumbprint}` with the ACME thumbprint value.

2. **Test Account Setup**  
    Submit a test domain using the `/domains` endpoint to verify the account is properly configured for ACME validation.

    ```bash
    curl -X POST localhost:8080/domains -H 'Content-Type: application/json' \
        -d '{"domain":"example.com","accountId":1234,"dcvRequestType":"ACME_DNS"}'
    ```

    Response:
    ```json
    {
      "id": 3,
      "domainName": "example.com",
      "accountId": 1234,
      "dcvType": "ACME_DNS",
      "status": "PENDING",
      "randomValueDetails": [
        {
         "randomValue": "UL7B61sn7scBMIczBDNl8aljVfQkSkAL",
         "email":null"
        }
      ]
    }

    ```
    If the account is not set up correctly, you may encounter the error:  
    `{"message":"Account not set up for ACME validation"}`. In this case, double-check the thumbprint and permissions.


3. **Create DNS record (First ensure zone exists)**

// Check if zone exists
curl -H 'X-API-Key: secret' http://localhost:8081/api/v1/servers/localhost/zones/example.com.

// If zone doesn't exist, create it first
curl -X POST http://localhost:8081/api/v1/servers/localhost/zones \
--header 'X-API-Key: secret' \
--header 'Content-Type: application/json' \
--data-raw '{
        "name": "example.com.",
        "kind": "Master",
        "nameservers": ["ns1.example.com."]
}'

// Then add the ACME challenge record
curl --location --request PATCH 'http://localhost:8081/api/v1/servers/localhost/zones/example.com.' \
--header 'X-API-Key: secret' \
--header 'Content-Type: application/json' \
--data-raw '{
        "rrsets": [
                {
                        "name": "_acme-challenge.example.com.",
                        "type": "TXT",
                        "ttl": 300,
                        "changetype": "REPLACE",
                        "records": [
                                {
                                        "content": "\"UL7B61sn7scBMIczBDNl8aljVfQkSkAL\"",
                                        "disabled": false
                                }
                        ]
                }
        ]
}'

4. **Validate**
```
curl -X PUT localhost:8080/domains/1 -H 'Content-Type: application/json' \
    -d '{"domain":"example.com","dcvRequestType":"ACME_DNS","randomValue":"UL7B61sn7scBMIczBDNl8aljVfQkSkAL"}'
// MPIC validates DNS from multiple perspectives
```

By completing these steps, the account will be ready for ACME validation.

## 2. ACME HTTP-01 Flow

### Steps for ACME HTTP-01 Validation

To configure an account for ACME HTTP-01 validation, follow these steps:

1. **Submit Domain**  
    Use the `/domains` endpoint to submit the domain for validation. Specify the `ACME_HTTP` request type.

    ```bash
    curl -X POST localhost:8080/domains -H 'Content-Type: application/json' \
        -d '{"domain":"example.com","dcvRequestType":"ACME_HTTP"}'
    ```

    Response:

    ```json
    {
      "id": 3,
      "domainName": "example.com",
      "dcvType": "ACME_HTTP",
      "status": "PENDING",
      "randomValueDetails": [
        {
         "randomValue": "abc123",
         "email": null
        }
      ]
    }
    ```

2. **Create Challenge File**  
    Generate the challenge file using the random value and thumbprint. Place the file in the `.well-known/acme-challenge/` directory.

    ```bash
    echo "abc123.YOUR_THUMBPRINT" > /.well-known/acme-challenge/abc123
    ```

3. **Validate Domain**  
    Use the `/domains/{id}` endpoint to validate the domain. Specify the `ACME_HTTP` request type and provide the random value.

    ```bash
    curl -X PUT localhost:8080/domains/3 -H 'Content-Type: application/json' \
        -d '{"dcvRequestType":"ACME_HTTP","randomValue":"abc123"}'
    ```

    Response:

    ```json
    {
      "id": 3,
      "domainName": "example.com",
      "dcvType": "ACME_HTTP",
      "status": "VALIDATED"
    }
    ```

By completing these steps, the domain will be validated using the ACME HTTP-01 challenge.

## Key Implementation Details

### AcmeValidationHandler

Core validation logic with two methods:

```java
public class AcmeValidationHandler {
    
    // DNS-01: Check TXT record via MPIC
    private AcmeValidationResponse validateUsingAcmeDns(AcmeValidationRequest request) {
        String hash = SHA256(request.getRandomValue() + "." + request.getAcmeThumbprint());
        MpicDnsDetails result = mpicDnsService.getDnsDetails("_acme-challenge." + domain, TXT);
        // Check if any DNS record contains the hash
    }
    
    // HTTP-01: Fetch file via MPIC  
    private AcmeValidationResponse validateUsingAcmeHttp(AcmeValidationRequest request) {
        String url = "http://" + domain + "/.well-known/acme-challenge/" + token;
        MpicFileDetails result = mpicFileService.getMpicFileDetails(List.of(url));
        // Check if file content equals "token.thumbprint"
    }
}
```

### AcmeType Enum

Maps ACME challenge types to CA/B Forum validation methods:

```java
public enum AcmeType {
    ACME_DNS_01("dns-01", DcvMethod.BR_3_2_2_4_7),     // DNS Change
    ACME_HTTP_01("http-01", DcvMethod.BR_3_2_2_4_19);  // ACME HTTP Challenge
}
```

### Error Handling

New `AcmeValidationException` captures the original request for debugging:

```java
public class AcmeValidationException extends ValidationException {
    private final AcmeValidationRequest acmeValidationRequest;
    
    // Provides full context when validation fails
}
```

## Testing Setup

### Integration Tests

```bash
# Start test environment
cd example-app && docker-compose up -d

# Run ACME DNS test
mvn test -Dtest=AcmeDnsMethodIT

# Run ACME HTTP test  
mvn test -Dtest=AcmeHttpMethodIT
```

### Manual Testing

```bash
# 1. Set thumbprint
curl -X POST "localhost:8080/accounts/1234/tokens?tokenKey=YOUR_THUMBPRINT"

# 2. Submit domain
curl -X POST localhost:8080/domains -H 'Content-Type: application/json' \
  -d '{"domain":"test.com","accountId":1234,"dcvRequestType":"ACME_DNS"}'

# 3. Create DNS record (example with PowerDNS)
curl -X PATCH localhost:8081/api/v1/servers/localhost/zones/test.com \
  -H 'X-API-Key: secret' -d '{"rrsets":[{...}]}'

# 4. Validate
curl -X PUT localhost:8080/domains/1 -H 'Content-Type: application/json' \
  -d '{"domain":"test.com","dcvRequestType":"ACME_DNS","randomValue":"abc123"}'
```

## Configuration Required

### MPIC Client Implementation

You must provide an MPIC client:

```java
DcvConfiguration config = DcvConfiguration.builder()
    .mpicClientInterface(new YourMpicClient()) // Required!
    .build();
```

## Common Issues

1. **Missing ACME thumbprint**: Call token API first
2. **Wrong API endpoint**: Use `PUT /domains/{id}` not `POST /domains/{id}/validate`
3. **DNS propagation**: Wait for DNS records to propagate before validation
4. **File permissions**: Ensure web server can serve `.well-known/acme-challenge/` files

## API Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/accounts/{id}/tokens?tokenKey={thumbprint}` | Set ACME thumbprint |
| POST | `/domains` | Submit domain |
| GET | `/domains/{id}` | Check status |
| PUT | `/domains/{id}` | Validate domain |

That's it. The implementation follows standard ACME RFC 8555 and integrates with your existing MPIC infrastructure.
