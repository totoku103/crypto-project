# Crypto Project

이 프로젝트는 다양한 암호화 알고리즘을 구현하고 테스트하는 라이브러리입니다. 순수 Java 구현과 최적화된 구현을 모두 포함하며, 다양한 테스트 벡터를 통해 검증됩니다.

## 목차
- [프로젝트 소개](#프로젝트-소개)
- [빌드 방법](#빌드-방법)
- [코드 스타일](#코드-스타일)
- [테스트 실행](#테스트-실행)
- [주요 모듈 및 패키지](#주요-모듈-및-패키지)

## 프로젝트 소개

`crypto-project`는 다음과 같은 암호화 기능을 제공합니다:

- **SHA-2**: SHA-256, SHA-512 해시 알고리즘 구현.
- **SHA-3**: 순수 Java 구현 및 JDK `MessageDigest`를 활용한 최적화된 SHA-3 (SHAKE 포함) 구현.
- **HMAC**: HMAC-SHA256 구현.
- **ARIA**: KISA(한국인터넷진흥원)에서 개발한 ARIA 블록 암호 알고리즘 구현 (ECB, CBC, GCM 모드 지원).
- **SEED**: KISA에서 개발한 SEED 블록 암호 알고리즘 구현 (ECB, CBC, GCM 모드 지원).

## 빌드 방법

이 프로젝트는 Gradle을 사용하여 빌드됩니다. 프로젝트를 빌드하려면 다음 명령어를 실행하세요:

```bash
./gradlew build
```

## 코드 스타일

이 프로젝트는 [Spotless Gradle Plugin](https://github.com/diffplug/spotless/tree/main/plugin-gradle)과 [Google Java Format](https://github.com/google/google-java-format)을 사용하여 코드 스타일을 관리합니다.

코드 스타일을 자동으로 포매팅하려면 다음 명령어를 실행하세요:

```bash
./gradlew spotlessApply
```

코드 스타일 준수 여부를 확인하려면 다음 명령어를 실행하세요:

```bash
./gradlew spotlessCheck
```

## 테스트 실행

프로젝트의 모든 테스트를 실행하려면 다음 명령어를 실행하세요:

```bash
./gradlew test
```

테스트는 각 암호화 알고리즘의 정확성을 검증하며, 특히 SHA-3 구현의 경우 한글과 이모지를 포함한 다양한 문자열을 사용합니다. SHA3 알고리즘을 지원하지 않는 JDK(예: 1.8)에서는 최적화 구현 관련 테스트가 자동으로 건너뛰며, 순수 Java 구현만 검증됩니다.

## 주요 모듈 및 패키지

`lib` 모듈은 프로젝트의 핵심 암호화 라이브러리를 포함합니다.

- `me.totoku103.crypto.java`: 순수 Java로 구현된 표준 암호화 알고리즘 (HMAC, SHA-2, SHA-3).
- `me.totoku103.crypto.kisa`: KISA에서 개발한 암호화 알고리즘 (ARIA, SEED, HMAC, SHA-2, SHA-3) 구현.
  - `me.totoku103.crypto.kisa.aria`: ARIA 블록 암호 구현.
  - `me.totoku103.crypto.kisa.seed`: SEED 블록 암호 구현.
- `me.totoku103.crypto.enums`: 암호화 관련 열거형.
- `me.totoku103.crypto.utils`: 유틸리티 클래스 (예: HexConverter, PaddingUtils).
