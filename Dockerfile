# Stage 1: Build stage
FROM --platform=$BUILDPLATFORM openjdk:8-jdk-alpine as build

WORKDIR /app

# Copy source code and build
COPY . .

RUN ./gradlew clean build

# Stage 2: Runtime stage
FROM --platform=$TARGETPLATFORM openjdk:8-jre-alpine

WORKDIR /app

# Copy built artifacts from the build stage
COPY --from=build /app/build/libs/forwardsecrecy.jar .

# Command to run the application
CMD ["java", "-jar", "forwardsecrecy.jar"]