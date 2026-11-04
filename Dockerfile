# ==========================================
# Stage 1: Build the Spring Boot JAR
# ==========================================
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app

# Gradle 캐싱을 위해 래퍼 및 설정 파일 먼저 복사
COPY gradlew .
COPY gradle gradle
COPY build.gradle settings.gradle ./
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon || true

# 소스코드 복사 및 빌드 (테스트는 별도 검증 완료되었으므로 생략하여 빌드 속도 극대화)
COPY src src
RUN ./gradlew bootJar -x test --no-daemon

# ==========================================
# Stage 2: Runtime Image with Git & Trivy
# ==========================================
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# 필수 유틸리티 및 Git 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Aqua Security 공식 Docker 이미지에서 Trivy 정적 바이너리 직접 복사 (스크립트 다운로드 오류 방지)
COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy

# Trivy 및 Git 설치 정상 확인
RUN git --version && trivy --version

# 빌드된 Spring Boot JAR 복사
COPY --from=builder /app/build/libs/*.jar app.jar

# 기본 포트 노출
EXPOSE 8080

# 보안을 위해 컨테이너 실행
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
