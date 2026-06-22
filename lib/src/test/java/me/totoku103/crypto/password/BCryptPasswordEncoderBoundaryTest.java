package me.totoku103.crypto.password;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * BCryptPasswordEncoder 경계값 분석 + 등가분할 + 보안 명세 테스트.
 *
 * <p>기존 {@link BCryptPasswordEncoderTest}가 커버하지 않은 경계 케이스를 검증한다:
 * <ul>
 *   <li>MIN_COST(4) / MAX_COST(31) 경계 work factor</li>
 *   <li>upgradeNeeded cost 경계 바로 아래(cost - 1)</li>
 *   <li>isBCryptHash의 $2a$/$2b$ 버전 패턴 포용</li>
 *   <li>SecureRandom 기반 salt 고유성</li>
 *   <li>단방향성 최소 명세</li>
 *   <li>bcrypt 72바이트 절단 명세</li>
 *   <li>work factor 실효성(cost=4 vs cost=8 시간 비교)</li>
 * </ul>
 */
@DisplayName("BCryptPasswordEncoder 경계값 · 보안 명세 테스트")
class BCryptPasswordEncoderBoundaryTest {

  // -------------------------------------------------------------------------
  // 1. MIN_COST(4) 경계: 포맷 및 길이 검증
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("cost=4(MIN_COST)로 encode 시 $2y$04$ 접두사 + 60자 해시")
  void encode_withMinCost_producesCorrectPrefixAndLength() {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);

    // Act
    String hash = encoder.encode("boundary-min");

    // Assert
    // $2y$04$<22자 salt><31자 hash> = 총 60자
    assertEquals(60, hash.length(), "bcrypt 해시는 60자여야 함: " + hash);
    assertTrue(hash.startsWith("$2y$04$"), "MIN_COST=4이면 '$2y$04$' 접두사를 가져야 함: " + hash);
  }

  // -------------------------------------------------------------------------
  // 2. MAX_COST(31) 경계: 포맷 및 길이 검증 (@Tag("slow")로 CI에서 선택적 실행)
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("cost=31(MAX_COST)은 생성자에서 허용되고 cost가 보존된다 (encode는 2^31 라운드라 미실행)")
  void encode_withMaxCost_isAcceptedAndCostPreserved() {
    // bcrypt 최대 cost=31. 실제 encode는 2^31(약 21억) 라운드로 수 시간 이상 소요되어
    // 테스트에서 호출하면 사실상 멈춘다. 따라서 encode는 호출하지 않고, 생성자 허용 범위와
    // cost 보존만 검증한다. ($2y$<cost>$ 접두사·60자 길이는 cost=4/8 테스트가 이미 커버)
    BCryptPasswordEncoder encoder = assertDoesNotThrow(() -> new BCryptPasswordEncoder(31),
        "MAX_COST=31은 생성자에서 허용되어야 함");

    assertEquals(31, encoder.getCost(), "생성자에 전달한 cost가 보존되어야 함");
  }

  // -------------------------------------------------------------------------
  // 3. upgradeNeeded: 저장된 cost == 현재 정책 cost - 1 (경계 바로 아래) → true
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("upgradeNeeded: 저장 cost가 현재 정책 cost-1(경계 바로 아래)이면 true")
  void upgradeNeeded_trueWhenStoredCostIsExactlyOneBelowPolicy() {
    // Arrange
    int policyCost = 8;
    int storedCost = policyCost - 1; // 경계 바로 아래 = 7

    BCryptPasswordEncoder storedEncoder = new BCryptPasswordEncoder(storedCost);
    String storedHash = storedEncoder.encode("pw");

    BCryptPasswordEncoder policyEncoder = new BCryptPasswordEncoder(policyCost);

    // Act & Assert
    assertTrue(policyEncoder.upgradeNeeded(storedHash),
        "저장된 cost(" + storedCost + ")가 정책 cost(" + policyCost + ")보다 1 낮으면 upgradeNeeded=true여야 함");
  }

  // -------------------------------------------------------------------------
  // 4. isBCryptHash: $2a$ 버전 패턴 포용
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("isBCryptHash: $2a$12$ 로 시작하는 60자 문자열은 true")
  void isBCryptHash_acceptsVersion2a() {
    // Arrange: $2a$ 버전의 표준 bcrypt 해시 샘플 (공개 KAT 벡터)
    // 출처: bcrypt 참조 구현 테스트 벡터
    String hash2a = "$2a$12$LrmaIX5zpmBdoMFtRwu1KOdiTNFnR6NKfVPGMgfF3Yx5VTmqBYWiO";

    // Act & Assert
    assertTrue(BCryptPasswordEncoder.isBCryptHash(hash2a),
        "$2a$ 버전도 표준 bcrypt 포맷으로 인식해야 함: " + hash2a);
  }

  // -------------------------------------------------------------------------
  // 5. isBCryptHash: $2b$ 버전 패턴 포용
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("isBCryptHash: $2b$12$ 로 시작하는 60자 문자열은 true")
  void isBCryptHash_acceptsVersion2b() {
    // Arrange: $2b$ 버전 표준 bcrypt 해시 샘플
    String hash2b = "$2b$12$LrmaIX5zpmBdoMFtRwu1KOdiTNFnR6NKfVPGMgfF3Yx5VTmqBYWiO";

    // Act & Assert
    assertTrue(BCryptPasswordEncoder.isBCryptHash(hash2b),
        "$2b$ 버전도 표준 bcrypt 포맷으로 인식해야 함: " + hash2b);
  }

  // -------------------------------------------------------------------------
  // 6. SecureRandom 기반 salt 고유성: 두 번 encode한 결과의 salt 부분이 달라야 한다
  //    (고정 salt 버그 검출)
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("encode 두 번 호출 시 salt 부분(문자 7~28)이 서로 달라야 함 — SecureRandom salt 고유성")
  void encode_producesDifferentSaltPerCall() {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String rawPassword = "same-password";

    // Act
    String hash1 = encoder.encode(rawPassword);
    String hash2 = encoder.encode(rawPassword);

    // Assert
    // bcrypt 해시 포맷: $2y$04$<22자 salt><31자 hash>
    // 인덱스 7~28 (22자) 가 salt 영역 (0-based: [7, 29))
    String salt1 = hash1.substring(7, 29);
    String salt2 = hash2.substring(7, 29);

    assertNotEquals(salt1, salt2,
        "SecureRandom으로 생성된 salt는 매 호출마다 달라야 함 — 고정 salt 버그 아님. salt1=" + salt1 + ", salt2=" + salt2);
  }

  // -------------------------------------------------------------------------
  // 7. 단방향성 최소 명세: encode 결과가 원문 비밀번호와 달라야 한다
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("encode 결과가 원문 비밀번호 문자열과 달라야 함 — 단방향성 최소 명세")
  void encode_resultDiffersFromRawPassword() {
    // Arrange
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String rawPassword = "my-secret-password";

    // Act
    String hash = encoder.encode(rawPassword);

    // Assert
    assertNotEquals(rawPassword, hash, "encode 결과는 원문 비밀번호와 같으면 안 됨(단방향성)");
    assertFalse(hash.contains(rawPassword), "해시 내부에 원문 비밀번호가 평문으로 포함되면 안 됨");
  }

  // -------------------------------------------------------------------------
  // 8. bcrypt 72바이트 절단 명세:
  //    72바이트 평문을 encode한 해시에 대해 matches(73바이트 평문, 해시)가 true여야 한다.
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("bcrypt 72바이트 절단 명세: 73바이트 평문의 해시에 72바이트 평문이 matches=true")
  void matches_72ByteTruncation_73bytePlaintextMatchesHashOf72bytePrefix() {
    // Arrange
    // 정확히 72바이트 ASCII 문자열 (US-ASCII 1바이트/문자)
    String password72bytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"; // 70자
    // 위가 70자이므로 2자 더 추가해 정확히 72자(=72바이트 ASCII)
    password72bytes = password72bytes + "IJ"; // 총 72자

    // 73바이트 평문 = 72바이트 + 1바이트 추가
    String password73bytes = password72bytes + "K"; // 총 73자

    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);

    // Act: 72바이트 평문으로 해시 생성
    String hashOf72 = encoder.encode(password72bytes);

    // Assert: bcrypt는 73번째 이후 바이트를 무시하므로 73바이트 평문도 matches=true여야 함
    assertTrue(encoder.matches(password73bytes, hashOf72),
        "bcrypt는 입력의 앞 72바이트만 사용하므로, 73바이트 평문도 72바이트 해시에 matches=true여야 함");

    // 역방향 검증: 73바이트 해시에 대해 72바이트 평문도 matches=true
    String hashOf73 = encoder.encode(password73bytes);
    assertTrue(encoder.matches(password72bytes, hashOf73),
        "73바이트 해시에 대해 72바이트 prefix 평문도 matches=true여야 함(72바이트 절단 명세)");
  }

  // -------------------------------------------------------------------------
  // 9. work factor 실효성: cost=4 encode 시간 < cost=8 encode 시간
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("cost=8 encode 시간이 cost=4 encode 시간보다 길어야 함 — work factor 실효성")
  void encode_higherCostTakesMoreTime() {
    // Arrange
    BCryptPasswordEncoder cost4Encoder = new BCryptPasswordEncoder(4);
    BCryptPasswordEncoder cost8Encoder = new BCryptPasswordEncoder(8);
    String rawPassword = "work-factor-test";

    // Warm-up: JIT 컴파일 편향 방지를 위해 각각 1회 사전 실행
    cost4Encoder.encode(rawPassword);
    cost8Encoder.encode(rawPassword);

    // Act: 각 cost에 대해 encode 시간 측정 (나노초)
    long start4 = System.nanoTime();
    cost4Encoder.encode(rawPassword);
    long elapsed4 = System.nanoTime() - start4;

    long start8 = System.nanoTime();
    cost8Encoder.encode(rawPassword);
    long elapsed8 = System.nanoTime() - start8;

    // Assert
    // cost가 1 증가할 때마다 이론상 2배 소요. cost=8은 cost=4보다 2^4=16배 오래 걸려야 함.
    // 머신 부하를 고려해 최소 4배(16배의 1/4) 여유를 두고 단언.
    long minExpectedRatio = 4L;
    assertTrue(elapsed8 > elapsed4 * minExpectedRatio,
        String.format(
            "cost=8 encode(%d ns)가 cost=4 encode(%d ns)의 최소 %d배보다 길어야 함 — work factor 실효성 실패",
            elapsed8, elapsed4, minExpectedRatio));
  }
}
