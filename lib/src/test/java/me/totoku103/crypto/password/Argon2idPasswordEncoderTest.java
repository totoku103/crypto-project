package me.totoku103.crypto.password;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;

/**
 * Argon2idPasswordEncoder 단위 테스트.
 *
 * <p>대부분의 테스트는 빠른 실행을 위해 작은 비용 파라미터(memory 256KiB, t=1, p=1)를 사용한다.
 * 기본 생성자(OWASP 권장 파라미터) 검증은 별도 테스트에서 다룬다.
 */
class Argon2idPasswordEncoderTest {

  /** 빠른 테스트용 저비용 인코더. */
  private final Argon2idPasswordEncoder encoder = new Argon2idPasswordEncoder(256, 1, 1);

  @Test
  void encode_returnsStandardPhcFormat() {
    String hash = encoder.encode("P@ssw0rd!");

    // $argon2id$v=19$m=256,t=1,p=1$<saltB64>$<hashB64>
    assertTrue(
        hash.matches("^\\$argon2id\\$v=19\\$m=256,t=1,p=1\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$"),
        "표준 Argon2id PHC 포맷이어야 함: " + hash);
    assertTrue(Argon2idPasswordEncoder.isArgon2idHash(hash));
  }

  @Test
  void encode_producesSalt16BytesAndHash32Bytes() {
    String hash = encoder.encode("length-check");

    String[] parts = hash.split("\\$");
    // ["", "argon2id", "v=19", "m=256,t=1,p=1", saltB64, hashB64]
    assertEquals(6, parts.length, "PHC는 6개 구획으로 분리되어야 함: " + hash);

    byte[] salt = Base64.getDecoder().decode(parts[4]);
    byte[] hashBytes = Base64.getDecoder().decode(parts[5]);

    assertEquals(16, salt.length, "salt는 16바이트(≥16byte 기준)여야 함");
    assertEquals(32, hashBytes.length, "hash는 32바이트(256비트 기준)여야 함");
  }

  @Test
  void encode_usesRandomSaltPerCall() {
    String h1 = encoder.encode("samePassword");
    String h2 = encoder.encode("samePassword");

    // 같은 원문이라도 salt가 매번 달라 결과가 달라야 함
    assertNotEquals(h1, h2);
  }

  @Test
  void matches_returnsTrueForCorrectPassword() {
    String hash = encoder.encode("correct-horse");
    assertTrue(encoder.matches("correct-horse", hash));
  }

  @Test
  void matches_returnsFalseForWrongPassword() {
    String hash = encoder.encode("correct-horse");
    assertFalse(encoder.matches("wrong-horse", hash));
  }

  @Test
  void matches_supportsUnicodePassword() {
    String raw = "한글비밀번호_123!@#";
    String hash = encoder.encode(raw);
    assertTrue(encoder.matches(raw, hash));
    assertFalse(encoder.matches("한글비밀번호_124!@#", hash));
  }

  @Test
  void matches_verifiesHashEncodedWithDifferentParameters() {
    // 저장 시점의 파라미터(PHC에 내장)로 재계산해야 하므로,
    // 현재 인코더 파라미터와 다른 파라미터로 만든 해시도 검증 가능해야 한다.
    Argon2idPasswordEncoder stored = new Argon2idPasswordEncoder(512, 2, 1);
    String hash = stored.encode("cross-param");

    Argon2idPasswordEncoder current = new Argon2idPasswordEncoder(256, 1, 1);
    assertTrue(current.matches("cross-param", hash), "PHC 내장 파라미터로 검증되어야 함");
  }

  @Test
  void matches_returnsFalseForNullOrMalformedHash() {
    assertFalse(encoder.matches("pw", null));
    assertFalse(encoder.matches("pw", ""));
    assertFalse(encoder.matches("pw", "not-an-argon2-hash"));
    // bcrypt 해시 형태도 형식 불일치로 false
    assertFalse(encoder.matches("pw", "$2y$12$LrmaIX5zpmBdoMFtRwu1KOdiTNFnR6NKfVPGMgfF3Yx5VTmqBYWiO"));
    // 레거시 ARIA 암호문(대문자 16진수) 형태도 false
    assertFalse(encoder.matches("pw", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
  }

  @Test
  void matches_returnsFalseForNullRawPassword() {
    String hash = encoder.encode("pw");
    assertFalse(encoder.matches(null, hash));
  }

  @Test
  void encode_rejectsNullPassword() {
    assertThrows(IllegalArgumentException.class, () -> encoder.encode(null));
  }

  @Test
  void parameters_areConfigurableAndReflectedInHash() {
    Argon2idPasswordEncoder custom = new Argon2idPasswordEncoder(1024, 3, 2);
    assertEquals(1024, custom.getMemoryKb());
    assertEquals(3, custom.getIterations());
    assertEquals(2, custom.getParallelism());

    String hash = custom.encode("pw");
    assertTrue(hash.startsWith("$argon2id$v=19$m=1024,t=3,p=2$"), "파라미터가 해시에 반영되어야 함: " + hash);
  }

  @Test
  void constructor_rejectsNonPositiveParameters() {
    assertThrows(IllegalArgumentException.class, () -> new Argon2idPasswordEncoder(0, 1, 1));
    assertThrows(IllegalArgumentException.class, () -> new Argon2idPasswordEncoder(256, 0, 1));
    assertThrows(IllegalArgumentException.class, () -> new Argon2idPasswordEncoder(256, 1, 0));
  }

  @Test
  void upgradeNeeded_trueForLegacyOrNonArgon2() {
    // null, 빈 값, bcrypt, 레거시 ARIA 형식 등 argon2id가 아니면 재해시 대상
    assertTrue(encoder.upgradeNeeded(null));
    assertTrue(encoder.upgradeNeeded(""));
    assertTrue(
        encoder.upgradeNeeded("$2y$12$LrmaIX5zpmBdoMFtRwu1KOdiTNFnR6NKfVPGMgfF3Yx5VTmqBYWiO"));
    assertTrue(encoder.upgradeNeeded("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
  }

  @Test
  void upgradeNeeded_trueWhenStoredParametersAreWeaker() {
    String weak = new Argon2idPasswordEncoder(256, 1, 1).encode("pw");
    // 저장된 메모리(256) < 현재 정책(512) → 재해시 필요
    Argon2idPasswordEncoder strongerMemory = new Argon2idPasswordEncoder(512, 1, 1);
    assertTrue(strongerMemory.upgradeNeeded(weak));

    // 저장된 반복(1) < 현재 정책(2) → 재해시 필요
    Argon2idPasswordEncoder strongerIterations = new Argon2idPasswordEncoder(256, 2, 1);
    assertTrue(strongerIterations.upgradeNeeded(weak));
  }

  @Test
  void upgradeNeeded_falseWhenParametersMeetPolicy() {
    String current = new Argon2idPasswordEncoder(256, 1, 1).encode("pw");
    Argon2idPasswordEncoder policy = new Argon2idPasswordEncoder(256, 1, 1);
    assertFalse(policy.upgradeNeeded(current));
  }

  @Test
  void upgradeNeeded_falseWhenStoredParametersAreStronger() {
    String strong = new Argon2idPasswordEncoder(512, 2, 1).encode("pw");
    Argon2idPasswordEncoder policy = new Argon2idPasswordEncoder(256, 1, 1);
    // 저장된 파라미터가 정책보다 강하면 재해시 불필요
    assertFalse(policy.upgradeNeeded(strong));
  }

  @Test
  void isArgon2idHash_detectsFormat() {
    assertTrue(Argon2idPasswordEncoder.isArgon2idHash(encoder.encode("pw")));
    assertFalse(Argon2idPasswordEncoder.isArgon2idHash(null));
    assertFalse(Argon2idPasswordEncoder.isArgon2idHash("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
    assertFalse(
        Argon2idPasswordEncoder.isArgon2idHash(
            "$2y$12$LrmaIX5zpmBdoMFtRwu1KOdiTNFnR6NKfVPGMgfF3Yx5VTmqBYWiO"));
  }

  @Test
  void defaultConstructor_usesOwaspRecommendedParameters() {
    Argon2idPasswordEncoder defaultEncoder = new Argon2idPasswordEncoder();
    assertEquals(47104, defaultEncoder.getMemoryKb(), "기본 메모리는 47104 KiB(46MiB, OWASP 옵션 A)여야 함");
    assertEquals(1, defaultEncoder.getIterations(), "기본 반복은 1이어야 함");
    assertEquals(1, defaultEncoder.getParallelism(), "기본 병렬도는 1이어야 함");

    // 기본 파라미터로도 정상 인코딩·검증 라운드트립이 동작해야 함
    String hash = defaultEncoder.encode("owasp-default");
    assertTrue(hash.startsWith("$argon2id$v=19$m=47104,t=1,p=1$"));
    assertTrue(defaultEncoder.matches("owasp-default", hash));
  }

  @Test
  void encode_resultDiffersFromRawPassword() {
    String raw = "my-secret-password";
    String hash = encoder.encode(raw);
    assertNotEquals(raw, hash, "encode 결과는 원문과 같으면 안 됨(단방향성)");
    assertFalse(hash.contains(raw), "해시 내부에 원문이 평문으로 포함되면 안 됨");
  }

  @Test
  void matches_verifiesLegacyVersion16Hash() {
    // 과거 Argon2 1.0(v=16)으로 생성된 해시도 올바른 비밀번호면 검증에 성공해야 한다.
    // (인코더는 항상 v=19로 생성하므로 v=16 해시는 BouncyCastle로 직접 만든다.)
    String legacyHash = encodeWithVersion(Argon2Parameters.ARGON2_VERSION_10, "legacy-pw", 256, 1, 1);
    assertTrue(legacyHash.startsWith("$argon2id$v=16$"), "v=16 해시여야 함: " + legacyHash);

    assertTrue(encoder.matches("legacy-pw", legacyHash), "v=16 해시도 올바른 비밀번호면 matches=true여야 함");
    assertFalse(encoder.matches("wrong-pw", legacyHash), "v=16 해시도 틀린 비밀번호면 matches=false여야 함");
  }

  @Test
  void matches_returnsFalseForUnknownVersion() {
    // 알 수 없는 버전(v=99)은 검증 대상이 아니므로 false.
    String hash = encoder.encode("pw");
    String tampered = hash.replaceFirst("\\$v=19\\$", "\\$v=99\\$");
    assertFalse(encoder.matches("pw", tampered), "알 수 없는 버전(v=99)은 false여야 함");
  }

  @Test
  void matches_returnsFalseForExcessiveMemoryWithoutOom() {
    // 신뢰할 수 없는 거대 메모리 파라미터(m=2147483647)는 OOM 없이 false로 처리되어야 한다.
    String hash = encoder.encode("pw");
    String tampered = hash.replaceFirst("m=256,", "m=2147483647,");
    assertFalse(encoder.matches("pw", tampered), "과도한 메모리 파라미터는 OOM 없이 false여야 함");
  }

  /** 지정한 Argon2 버전으로 PHC 포맷 해시 문자열을 생성한다(테스트 전용 헬퍼). */
  private static String encodeWithVersion(int version, String raw, int memoryKb, int t, int p) {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    Argon2Parameters params =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(version)
            .withMemoryAsKB(memoryKb)
            .withIterations(t)
            .withParallelism(p)
            .withSalt(salt)
            .build();
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(params);
    byte[] out = new byte[32];
    generator.generateBytes(raw.getBytes(StandardCharsets.UTF_8), out);

    Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
    return "$argon2id$v="
        + version
        + "$m="
        + memoryKb
        + ",t="
        + t
        + ",p="
        + p
        + "$"
        + b64.encodeToString(salt)
        + "$"
        + b64.encodeToString(out);
  }
}
