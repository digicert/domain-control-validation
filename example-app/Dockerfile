# Use the official OpenJDK 21 slim image
FROM openjdk:21-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the application JAR file to the container
COPY target/example-app-1.0-SNAPSHOT.jar /app/

# Install curl (if your application depends on it)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Download the public suffix list (if needed by your application)
RUN mkdir -p /usr/local/share && \
    curl -o /usr/local/share/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat

# Expose the port your application listens on
EXPOSE 8080

# Run the JAR file
CMD ["java", "-jar", "/app/example-app-1.0-SNAPSHOT.jar"]
