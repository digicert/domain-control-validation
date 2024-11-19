# example-app
The example-app is a reference implementation of the domain-control-validation library. This can be used as an example 
of how to call the API is domain-control-validation. This example-app includes a REST API implementation that uses the
domain-control-validation and full flow integration tests of the BRs implemented in domain-control validation.

> The example-app is not a production ready app. It is a reference implementation and should be used as such.


## Running the example-app
The example-app can be run using the following command:
```mvn spring-boot:run```

The example-app will start on port 8080. The API can be accessed at `http://localhost:8080/validate-domain-control`

## API
The example-app exposes a REST API that can be used to validate domain control for a domain. The API can be accessed at
`http://localhost:8080/validate-domain-control`


## Integration Tests
The integration tests are located in the `src/test/java/com/digicert/validation` directory. These have a 'IT' suffix.
The integration tests rely on various subsystems such as mysql, powerdns to be running. A docker-compose file is used to 
start these services and an instance of the example-app. The integration tests will run against the example-app instance.

The Maven Failsafe Plugin is used to run the integration tests (code snippet from the pom.xml for the example-app):
```
<!-- Failsafe Plugin for Integration Tests -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-failsafe-plugin</artifactId>
```

### Running Integration Tests
These can be run using the maven test goal.
```mvn clean verify```

### Debugging or Executing the Integration Tests in an IDE
1.  first start the docker-compose file
    ``` docker-compose -f ./example-app/docker-compose.yml up -d```
2. Execute or debug the integration tests normally in your IDE.