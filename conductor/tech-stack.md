# Technology Stack

| Area | Technology |
| --- | --- |
| Language | Java 21 |
| Build | Maven multi-module reactor |
| Core library | dnsjava, Apache HttpComponents 5, Commons Net, Guava, ICU4J, Bouncy Castle |
| Logging and boilerplate | SLF4J, Logback, Lombok |
| Unit tests | JUnit Jupiter, Mockito, MockServer |
| Reference integration tests | Maven Failsafe, Docker Compose, MySQL, PowerDNS |
| Quality | JaCoCo coverage profile, SonarQube, GitHub Actions |

[pom.xml](../pom.xml) defines the reactor. [library/pom.xml](../library/pom.xml) and [example-app/pom.xml](../example-app/pom.xml) define module dependencies and test lifecycles.
