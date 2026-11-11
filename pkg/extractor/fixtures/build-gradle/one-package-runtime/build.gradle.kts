plugins {
  `java-library`
}

repositories {
  mavenCentral()
}

dependencies {
  runtimeOnly("org.springframework.security:spring-security-crypto:5.8.0")
}

dependencyLocking {
  lockAllConfigurations()
}
