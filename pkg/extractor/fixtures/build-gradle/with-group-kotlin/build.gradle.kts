plugins {
  `java-library`
}

group = "com.example"

repositories {
  mavenCentral()
}

dependencies {
  implementation("org.springframework.security:spring-security-crypto:5.7.3")
}

dependencyLocking {
  lockAllConfigurations()
}
