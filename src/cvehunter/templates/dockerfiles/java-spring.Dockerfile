FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /app
COPY . .
RUN ./mvnw package -DskipTests 2>/dev/null || ./gradlew bootJar 2>/dev/null || true

FROM eclipse-temurin:17-jre-jammy

ARG JAR_FILE

WORKDIR /app
COPY --from=build /app/target/*.jar app.jar 2>/dev/null || true
COPY --from=build /app/build/libs/*.jar app.jar 2>/dev/null || true

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
