# 비밀번호 DB 암호화 저장 기준 충족 증적자료

## 1. 검토 기준

> 비밀번호 DB 암호화 저장 기준: **단방향 HASH 알고리즘 + salt 적용**
> (단, HASH 알고리즘은 **256비트 이상**이어야 하며, salt는 **16bytes 이상**, **사용자마다 다르게 랜덤 생성** 필요)

## 2. 적용 알고리즘

| 항목 | 내용 |
|------|------|
| 알고리즘 | **Argon2id** (메모리-하드 단방향 KDF) |
| 구현 라이브러리 | BouncyCastle `bcprov-jdk18on` 1.81 (`Argon2BytesGenerator`) |
| 표준 | RFC 9106 (Argon2), [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) 1순위 권장 알고리즘 |
| 저장 포맷 | 표준 PHC 문자열 (파라미터·salt 내장, self-contained) |
| 구현 클래스 | `me.totoku103.crypto.password.Argon2idPasswordEncoder` |

### 2.1 기본 파라미터 (OWASP 권장 옵션 A)

| 파라미터 | 값 | 비고 |
|----------|-----|------|
| 메모리 비용 (m) | 47104 KiB = **46 MiB** | OWASP 권장 옵션 A |
| 반복 횟수 (t) | **1** | 46MiB와 짝을 이루는 권장값 |
| 병렬도 (p) | **1** | |
| salt 길이 | **16 bytes** | `SecureRandom` 사용자별 랜덤 |
| 해시 출력 길이 | **32 bytes = 256 bits** | |

## 3. 기준별 충족 매핑

| 검토 기준 | 충족 | 구현 근거 | 검증 테스트 |
|-----------|:----:|-----------|-------------|
| 단방향 HASH 알고리즘 | ✅ | Argon2id는 복호화 불가능한 단방향 KDF. `encode()` 결과에 원문이 포함되지 않음 | `encode_resultDiffersFromRawPassword` |
| **HASH 256비트 이상** | ✅ | 해시 출력 `HASH_LENGTH = 32` bytes = **256 bits** | `encode_producesSalt16BytesAndHash32Bytes` |
| salt **16bytes 이상** | ✅ | `SALT_LENGTH = 16` bytes | `encode_producesSalt16BytesAndHash32Bytes` |
| salt **사용자마다 랜덤** | ✅ | `SecureRandom.nextBytes(salt)`를 `encode()` 호출마다 실행 | `encode_usesRandomSaltPerCall` |

> **참고 — bcrypt 대비 개선점:** 기존 bcrypt는 해시 출력이 184비트로 "256비트 이상" 기준을 문자 그대로 충족하지 못했으나, Argon2id는 해시 출력 길이를 32바이트(256비트)로 지정하여 기준을 **명시적으로 충족**한다.

## 4. 저장 포맷 (PHC 문자열)

```
$argon2id$v=19$m=47104,t=1,p=1$<base64(salt)>$<base64(hash)>
```

- `v=19` : Argon2 버전 1.3
- `m`, `t`, `p` : 메모리·반복·병렬 파라미터
- salt와 hash는 패딩 없는 Base64로 인코딩
- 파라미터와 salt가 문자열에 모두 포함되어 **별도 컬럼 없이 검증 가능**

예시 구조(값은 매 호출마다 랜덤 salt로 달라짐):

```
$argon2id$v=19$m=47104,t=1,p=1$<22자 base64 salt>$<43자 base64 hash>
```

## 5. 보안 설계 세부

| 항목 | 설명 |
|------|------|
| 사용자별 랜덤 salt | `SecureRandom`(CSPRNG)으로 매 인코딩마다 16바이트 생성 → rainbow table 무력화 |
| 메모리-하드 | 46MiB 메모리를 요구해 GPU·ASIC 대량 병렬 공격 비용을 크게 증가 |
| 상수 시간 비교 | 검증 시 `MessageDigest.isEqual`로 타이밍 공격 방지 |
| 레거시 버전 호환 | 검증(`matches`)은 저장된 해시의 버전(v=16/v=19)으로 재계산하여 과거 해시도 정상 인증 |
| 자원 고갈 방지 | 신뢰할 수 없는 입력의 과도한 메모리 파라미터(m > 1 GiB)는 OOM 없이 불일치 처리 |

## 6. 검증 결과

JUnit 5 기반 단위·경계·보안 명세 테스트 **22개 전부 통과**.

| 검증 항목 | 테스트 |
|-----------|--------|
| 표준 PHC 포맷 생성 | `encode_returnsStandardPhcFormat` |
| salt 16byte / hash 32byte(256bit) | `encode_producesSalt16BytesAndHash32Bytes` |
| 사용자별 랜덤 salt | `encode_usesRandomSaltPerCall` |
| 정상 비밀번호 검증 성공 | `matches_returnsTrueForCorrectPassword` |
| 틀린 비밀번호 검증 실패 | `matches_returnsFalseForWrongPassword` |
| 유니코드 비밀번호 | `matches_supportsUnicodePassword` |
| 단방향성(원문 미포함) | `encode_resultDiffersFromRawPassword` |
| 기본 파라미터(OWASP 옵션 A) | `defaultConstructor_usesOwaspRecommendedParameters` |
| 레거시 v=16 해시 검증 | `matches_verifiesLegacyVersion16Hash` |
| 자원 고갈 방지 | `matches_returnsFalseForExcessiveMemoryWithoutOom` |

### 재현 방법

```bash
./gradlew :lib:test --tests "me.totoku103.crypto.password.Argon2idPasswordEncoderTest"
```

## 7. 실행 예시 (실제 해시 값)

원문 `P@ssw0rd!` 를 기본 파라미터로 두 번 인코딩한 실제 출력이다.

```
원문 비밀번호 : P@ssw0rd!
해시 결과 #1  : $argon2id$v=19$m=47104,t=1,p=1$y3HEkn9GhdJ2yxqMVjv86Q$fwAM/kO2m2HEWfkzR2cjfpM9r8wS8pdFTgNCyu5Qv6M
해시 결과 #2  : $argon2id$v=19$m=47104,t=1,p=1$NjeCI76Pv4fYnuHVlEW1lg$C6wYEuT038eg2VQhv051j0TjIop5wwD2ZBjkcfZTNOY
```

### 7.1 PHC 포맷 분해 — salt 위치

```
$argon2id$v=19$m=47104,t=1,p=1$ y3HEkn9GhdJ2yxqMVjv86Q $ fwAM/kO2m2HEWfkzR2cjfpM9r8wS8pdFTgNCyu5Qv6M
 └ 알고리즘  └버전 └ 파라미터       └─ salt (base64) ─┘   └──────── hash (base64) ────────┘
```

| 구획 | 값 | 의미 |
|------|-----|------|
| 알고리즘 | `argon2id` | 단방향 해시 |
| 버전 | `v=19` | Argon2 1.3 |
| 파라미터 | `m=47104,t=1,p=1` | 메모리 46MiB, 반복 1, 병렬 1 |
| **salt** | `y3HEkn9GhdJ2yxqMVjv86Q` | base64 → 디코딩 시 **16 bytes** |
| hash | `fwAM/kO2...` | base64 → 디코딩 시 **32 bytes(256 bits)** |

### 7.2 salt 적용 확인 결과

```
[salt 확인]
  salt 길이 : 16 bytes (기준: 16 이상)        ✅
  hash 길이 : 32 bytes = 256 bits (기준: 256 이상)  ✅

[사용자별 랜덤 salt 증명]  ← 같은 비밀번호를 두 번 해시했으나 salt가 다름
  #1 salt : y3HEkn9GhdJ2yxqMVjv86Q
  #2 salt : NjeCI76Pv4fYnuHVlEW1lg
  두 salt가 서로 다른가? true            ✅

[검증]
  matches(올바른 비밀번호) : true         ✅
  matches(틀린 비밀번호)   : false        ✅
```

- **salt 내장 확인:** 해시 문자열을 `$`로 분리했을 때 5번째 토큰이 salt이며, base64 디코딩 시 정확히 16바이트다.
- **사용자별 랜덤 확인:** 동일 원문을 두 번 인코딩해도 salt와 결과가 완전히 다르다 → `SecureRandom`으로 매번 새 salt 생성.

명령줄에서 salt만 추출하려면:

```bash
HASH='$argon2id$v=19$m=47104,t=1,p=1$y3HEkn9GhdJ2yxqMVjv86Q$fwAM/kO2m2HEWfkzR2cjfpM9r8wS8pdFTgNCyu5Qv6M'
echo "$HASH" | cut -d'$' -f5    # → y3HEkn9GhdJ2yxqMVjv86Q (salt, base64)
```

> 위 해시 값은 시연용 실제 출력이며, salt가 매 호출마다 랜덤 생성되므로 재실행 시 값은 달라진다.

## 8. 결론

Argon2id 기반 비밀번호 저장 구현은 검토 기준의 4개 요건
(**단방향 HASH / 256비트 이상 / salt 16bytes 이상 / 사용자별 랜덤 salt**)을
**모두 명시적으로 충족**하며, OWASP 1순위 권장 알고리즘과 권장 파라미터를 적용하였다.
