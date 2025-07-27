# Crypto Project

한국 표준 암호화 알고리즘을 구현한 Java 라이브러리입니다.

## 구조

### 새로운 아키텍처

```
me.totoku103.crypto/
├── core/                    # 핵심 인터페이스 및 추상 클래스
│   ├── CryptoAlgorithm.java
│   ├── BlockCipher.java
│   ├── HashAlgorithm.java
│   ├── AbstractHashAlgorithm.java
│   ├── factory/             # 팩토리 패턴
│   │   └── CryptoFactory.java
│   ├── utils/               # 통합 유틸리티 클래스
│   │   └── ByteUtils.java   # 16진수 변환, 패딩, 바이트 조작
│   └── exception/           # 예외 처리
│       └── CryptoException.java
├── algorithms/              # 알고리즘 구현
│   ├── hash/                # 해시 알고리즘
│   │   ├── Sha256Jdk.java
│   │   └── Sha256Kisa.java
│   └── cipher/              # 블록 암호화 알고리즘
│       ├── SeedBlockCipher.java
│       └── AriaBlockCipher.java
├── example/                 # 사용 예제
│   └── CryptoExample.java
└── legacy/                  # 기존 구현 (하위 호환성)
    ├── java/
    └── kisa/
```

## SOLID 원칙 적용

### 1. Single Responsibility Principle (SRP)
- 각 클래스가 단일 책임을 가짐
- `CryptoAlgorithm`: 알고리즘 기본 정보
- `BlockCipher`: 블록 암호화 기능
- `HashAlgorithm`: 해시 기능
- `ByteUtils`: 바이트 조작 유틸리티

### 2. Open/Closed Principle (OCP)
- `AbstractHashAlgorithm`: 확장에 열려있고 수정에 닫혀있음
- 새로운 알고리즘 추가 시 기존 코드 수정 없이 확장 가능

### 3. Liskov Substitution Principle (LSP)
- 모든 구현체가 인터페이스를 완전히 구현
- `Sha256Jdk`와 `Sha256Kisa`가 `HashAlgorithm`을 대체 가능

### 4. Interface Segregation Principle (ISP)
- `CryptoAlgorithm`: 기본 정보만
- `BlockCipher`: 암호화/복호화 기능
- `HashAlgorithm`: 해시 기능

### 5. Dependency Inversion Principle (DIP)
- `CryptoFactory`: 구체 클래스가 아닌 인터페이스에 의존
- 의존성 주입을 통한 느슨한 결합

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
String hash = sha256Kisa.hashToHex("Hello".getBytes());
```

### 블록 암호화 사용

```java
// SEED 암호화
BlockCipher seedCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.SEED);
byte[] encrypted = seedCipher.encrypt(plaintext, key);
byte[] decrypted = seedCipher.decrypt(encrypted, key);

// ARIA 암호화
BlockCipher ariaCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.ARIA);
byte[] encrypted = ariaCipher.encrypt(plaintext, key);
byte[] decrypted = ariaCipher.decrypt(encrypted, key);
```

## 지원하는 알고리즘

### 해시 알고리즘
- SHA-256 (JDK 구현)
- SHA-256 (KISA 구현)

### 블록 암호화 알고리즘
- SEED (128-bit)
- ARIA (128-bit)

## 빌드 및 실행

```bash
# 빌드
./gradlew build

# 테스트 실행
./gradlew test

# 예제 실행
./gradlew run
```

## 기존 코드와의 호환성

기존 `java` 및 `kisa` 패키지의 구현은 `legacy` 패키지로 이동하여 하위 호환성을 유지합니다.

## 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다.
