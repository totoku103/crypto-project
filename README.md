# Crypto Project

## 소개

이 프로젝트는 다양한 암호화 알고리즘(해시, 블록암호 등)을 SOLID 원칙에 따라 구조화하여, 확장성과 유지보수성을 극대화한 Java 암호화 라이브러리입니다.

- **SOLID 원칙** 기반의 구조
- **팩토리 패턴**으로 알고리즘 생성
- **유틸리티 통합**: `ByteUtils` 중심
- **테스트 코드**: 통합/단위/예외/경계/성능 테스트 체계
- **레거시 호환**: 기존 KISA/JDK 구현과의 호환성 유지

---

## 프로젝트 구조

```
lib/src/main/java/me/totoku103/crypto/
  core/           # 인터페이스, 추상클래스, 팩토리, 예외, 유틸리티
  algorithms/     # SOLID 기반 알고리즘 구현 (hash, cipher)
  kisa/           # KISA 레거시 구현
  java/           # JDK 레거시 구현
  legacy/         # 이전 HexConverter, PaddingUtils 등
```

### 주요 클래스
- `core/CryptoAlgorithm`, `BlockCipher`, `HashAlgorithm`: 핵심 인터페이스
- `core/factory/CryptoFactory`: 팩토리 패턴 구현
- `core/utils/ByteUtils`: 바이트/패딩/16진수 유틸리티 (HexConverter, PaddingUtils 통합)
- `algorithms/hash/Sha256Jdk`, `Sha256Kisa`: 해시 알고리즘 구현
- `algorithms/cipher/SeedBlockCipher`, `AriaBlockCipher`: 블록 암호화 구현

---

## SOLID 설계 원칙 적용

1. **SRP**: 각 클래스는 단일 책임만 가짐
2. **OCP**: 새로운 알고리즘 추가 시 기존 코드 수정 없이 확장 가능
3. **LSP**: 모든 구현체가 인터페이스를 완전히 구현
4. **ISP**: 인터페이스 분리, 필요한 기능만 제공
5. **DIP**: 팩토리/인터페이스 기반 의존성

---

## 사용법

### 유틸리티 사용
```java
// 16진수 변환
String hex = ByteUtils.stringToHex("Hello");
String text = ByteUtils.hexToString(hex);

// 패딩
byte[] padded = ByteUtils.addPadding(data);
byte[] unpadded = ByteUtils.removePadding(padded);

// 바이트 변환
int value = ByteUtils.bytesToInt(bytes, 0);
ByteUtils.intToBytes(value, result, 0);
```

### 해시 알고리즘 사용
```java
// JDK SHA-256
HashAlgorithm sha256Jdk = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_JDK);
String hash = sha256Jdk.hashToHex("Hello".getBytes());

// KISA SHA-256
HashAlgorithm sha256Kisa = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_KISA);
String hash2 = sha256Kisa.hashToHex("Hello".getBytes());
```

### 블록 암호화 사용
```java
// SEED 암호화
BlockCipher seedCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.SEED);
byte[] encrypted = seedCipher.encrypt(plaintext, key);
byte[] decrypted = seedCipher.decrypt(encrypted, key);

// ARIA 암호화
BlockCipher ariaCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.ARIA);
byte[] encrypted2 = ariaCipher.encrypt(plaintext, key);
byte[] decrypted2 = ariaCipher.decrypt(encrypted2, key);
```

---

## 지원 알고리즘

### 해시 알고리즘
- SHA-256 (JDK)
- SHA-256 (KISA)

### 블록 암호화 알고리즘
- SEED (128-bit)
- ARIA (128-bit)
- AES (256-bit)

---

## 테스트

프로젝트는 JUnit 5 기반의 체계적인 테스트를 제공합니다.

### 테스트 실행
```bash
# 전체 테스트 실행
./gradlew test

# 특정 테스트 클래스 실행
./gradlew test --tests "*IntegratedCryptoTest*"

# 특정 패키지 테스트 실행
./gradlew test --tests "me.totoku103.crypto.core.*"
```

### 테스트 구조
- `core/BaseCryptoTest`: 모든 테스트의 기본 클래스, 공통 유틸리티 제공
- `core/IntegratedCryptoTest`: 모든 알고리즘 통합 테스트
- `core/ExceptionTest`: 예외/경계 테스트
- `core/factory/CryptoFactoryTest`: 팩토리 패턴 테스트
- `core/utils/ByteUtilsTest`: 유틸리티 테스트
- `algorithms/hash/Sha256JdkTest`, `cipher/SeedBlockCipherTest` 등: 알고리즘별 단위 테스트
- `kisa/`, `java/`: 레거시 테스트 (하위 호환성)

### Java 호환성
- Gradle Toolchain으로 **JDK 8**을 강제하며, `./gradlew test` 실행 시 Temurin 1.8(AMD64)으로 전체 테스트를 검증합니다.

### 테스트 커버리지
- 단위 테스트: 각 알고리즘의 개별 기능
- 통합 테스트: 팩토리 기반 생성/사용
- 예외 테스트: 잘못된 입력, 경계값
- 성능 테스트: 대용량 데이터 처리

---

## 빌드 및 실행
```bash
# 코드 포맷팅
./gradlew spotlessApply

# 빌드
./gradlew build

# 테스트
./gradlew test
```

---

## 레거시/하위 호환성
- 기존 `HexConverter`, `PaddingUtils` 등은 `ByteUtils`로 통합
- `legacy` 패키지에 Deprecated 처리로 이전 코드도 사용 가능
- KISA/JDK 레거시 알고리즘도 테스트 및 사용 가능

---

## 라이선스
MIT License
