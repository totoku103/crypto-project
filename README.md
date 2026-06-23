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

### 비밀번호 해싱 (단방향, salt 적용)
사용자 비밀번호 저장 전용 모듈입니다. 블록 암호와 달리 **복호화가 불가능한 단방향 해시**이며,
인코딩 시 사용자별 16바이트 랜덤 salt(`SecureRandom`)가 자동 생성되어 결과 문자열에 포함됩니다.
같은 비밀번호라도 매번 다른 해시가 생성되어 레인보우 테이블 공격에 안전합니다.

```java
import me.totoku103.crypto.password.PasswordEncoder;
import me.totoku103.crypto.password.BCryptPasswordEncoder;

// work factor(cost) 기본값 12. 필요 시 new BCryptPasswordEncoder(13)으로 강도 조정
PasswordEncoder encoder = new BCryptPasswordEncoder();

// 비밀번호 저장 시
String stored = encoder.encode("rawPassword");   // 예: $2y$12$... (60자, salt 포함)

// 로그인 검증 시
boolean ok = encoder.matches("rawPassword", stored);

// 점진적 마이그레이션: 저장된 해시가 레거시이거나 cost가 낮으면 재해시 필요
if (encoder.upgradeNeeded(stored)) {
    String rehashed = encoder.encode("rawPassword"); // 로그인 성공 시점에 재저장
}
```

> 알고리즘: bcrypt(OpenBSD `$2y$` 표준 포맷, BouncyCastle `OpenBSDBCrypt`).
> KT 비밀번호 저장 기준(단방향 HASH, salt ≥16byte 사용자별 랜덤) 충족.
> 참고: bcrypt는 비밀번호 앞 72바이트만 사용합니다.

#### Argon2id (권장)

`Argon2idPasswordEncoder`는 메모리-하드 단방향 해시로, **해시 출력 256비트(32byte)**를 보장합니다.
bcrypt와 동일하게 16바이트 사용자별 랜덤 salt(`SecureRandom`)를 적용하며, 결과는 표준 PHC 문자열에
파라미터·salt가 모두 포함(self-contained)되어 별도 컬럼 없이 검증됩니다.

```java
import me.totoku103.crypto.password.PasswordEncoder;
import me.totoku103.crypto.password.Argon2idPasswordEncoder;

// 기본 파라미터: OWASP 옵션 A (메모리 46MiB, 반복 1, 병렬 1)
PasswordEncoder encoder = new Argon2idPasswordEncoder();
// 필요 시 new Argon2idPasswordEncoder(memoryKb, iterations, parallelism)로 조정

// 비밀번호 저장 시
String stored = encoder.encode("rawPassword");
// 예: $argon2id$v=19$m=47104,t=1,p=1$<base64 salt>$<base64 hash>

// 로그인 검증 시
boolean ok = encoder.matches("rawPassword", stored);

// 점진적 마이그레이션: 저장된 파라미터가 현재 정책보다 낮으면 재해시 필요
if (encoder.upgradeNeeded(stored)) {
    String rehashed = encoder.encode("rawPassword");
}
```

> 알고리즘: Argon2id(표준 PHC 포맷, BouncyCastle `Argon2BytesGenerator`), OWASP 1순위 권장.
> 비밀번호 저장 기준(단방향 HASH **256비트 이상**, salt ≥16byte 사용자별 랜덤)을 명시적으로 충족합니다.
> 검증(`matches`)은 저장된 버전(v=16/v=19)으로 수행되어 레거시 Argon2 해시도 인증할 수 있습니다.
> 자세한 기준 충족 근거는 [`docs/password-encryption-evidence.md`](docs/password-encryption-evidence.md) 참고.

---

## 지원 알고리즘

### 해시 알고리즘
- SHA-256 (JDK)
- SHA-256 (KISA)

### 블록 암호화 알고리즘
- SEED (128-bit)
- ARIA (128-bit)
- AES (256-bit)

### 비밀번호 해시 알고리즘
- bcrypt (`$2y$`, work factor 설정 가능, 16byte 랜덤 salt 자동 적용)
- Argon2id (PHC 포맷, 256bit 해시 출력, 16byte 랜덤 salt, OWASP 권장 파라미터)

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
