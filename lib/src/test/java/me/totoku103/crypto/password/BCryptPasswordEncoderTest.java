package me.totoku103.crypto.password;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** BCryptPasswordEncoder 단위 테스트. */
class BCryptPasswordEncoderTest {

  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  @Test
  void encode_returnsStandardBcryptFormat() {
    String hash = encoder.encode("P@ssw0rd!");

    // $2y$<cost>$<22자 salt><31자 hash> = 총 60자
    assertEquals(60, hash.length());
    assertTrue(hash.matches("^\\$2[aby]\\$\\d{2}\\$.{53}$"), "표준 bcrypt 포맷이어야 함: " + hash);
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
  void matches_returnsFalseForNullOrMalformedHash() {
    assertFalse(encoder.matches("pw", null));
    assertFalse(encoder.matches("pw", ""));
    assertFalse(encoder.matches("pw", "not-a-bcrypt-hash"));
    // 레거시 ARIA 암호문(대문자 16진수) 형태도 형식 불일치로 false
    assertFalse(encoder.matches("pw", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
  }

  @Test
  void encode_rejectsNullPassword() {
    assertThrows(IllegalArgumentException.class, () -> encoder.encode(null));
  }

  @Test
  void cost_isConfigurableAndReflectedInHash() {
    BCryptPasswordEncoder strong = new BCryptPasswordEncoder(13);
    String hash = strong.encode("pw");
    assertEquals(13, strong.getCost());
    assertTrue(hash.startsWith("$2y$13$"), "cost가 해시에 반영되어야 함: " + hash);
  }

  @Test
  void cost_outOfRangeThrows() {
    assertThrows(IllegalArgumentException.class, () -> new BCryptPasswordEncoder(3));
    assertThrows(IllegalArgumentException.class, () -> new BCryptPasswordEncoder(32));
  }

  @Test
  void upgradeNeeded_trueForLegacyOrNonBcrypt() {
    // null, 빈 값, 레거시 ARIA 형식 등 bcrypt가 아니면 재해시 대상
    assertTrue(encoder.upgradeNeeded(null));
    assertTrue(encoder.upgradeNeeded(""));
    assertTrue(encoder.upgradeNeeded("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
  }

  @Test
  void upgradeNeeded_trueWhenStoredCostIsLower() {
    String weak = new BCryptPasswordEncoder(10).encode("pw");
    BCryptPasswordEncoder current = new BCryptPasswordEncoder(12);
    // 저장된 cost(10) < 현재 정책(12) → 재해시 필요
    assertTrue(current.upgradeNeeded(weak));
  }

  @Test
  void upgradeNeeded_falseWhenCostMeetsPolicy() {
    String strong = new BCryptPasswordEncoder(12).encode("pw");
    BCryptPasswordEncoder current = new BCryptPasswordEncoder(12);
    assertFalse(current.upgradeNeeded(strong));
  }

  @Test
  void isBCryptHash_detectsFormat() {
    assertTrue(BCryptPasswordEncoder.isBCryptHash(encoder.encode("pw")));
    assertFalse(BCryptPasswordEncoder.isBCryptHash(null));
    assertFalse(BCryptPasswordEncoder.isBCryptHash("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4"));
  }
}
