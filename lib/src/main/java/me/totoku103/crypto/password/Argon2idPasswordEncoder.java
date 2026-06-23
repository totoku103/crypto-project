package me.totoku103.crypto.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id 기반 {@link PasswordEncoder} 구현.
 *
 * <p>BouncyCastle {@link Argon2BytesGenerator}를 사용하며, 인코딩 시 {@link SecureRandom}으로 16바이트
 * 랜덤 salt를 생성하고 256비트(32바이트) 해시를 산출한다. 결과는 표준 PHC 문자열 포맷
 * {@code $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>} 로, 파라미터와 salt가
 * 모두 포함(self-contained)되어 별도 컬럼 없이 검증할 수 있다.
 *
 * <p><b>비밀번호 DB 암호화 저장 기준 충족:</b>
 * <ul>
 *   <li>단방향 HASH: Argon2id(메모리-하드 단방향 KDF)</li>
 *   <li>HASH 출력 256비트: {@link #HASH_LENGTH}=32바이트</li>
 *   <li>salt 16바이트 이상: {@link #SALT_LENGTH}=16바이트</li>
 *   <li>사용자별 랜덤 salt: {@link SecureRandom}으로 encode마다 생성</li>
 * </ul>
 *
 * <p>OWASP 권장 파라미터(메모리 46MiB, 반복 1, 병렬 1 — OWASP 옵션 A)를 기본값으로 사용한다.
 *
 * <p><b>검증 시 버전 처리:</b> 인코딩은 항상 최신 Argon2 1.3(v=19)으로 수행하지만, 검증({@link #matches})은
 * 저장된 해시에 기록된 버전(1.0=v=16 또는 1.3=v=19)으로 재계산한다. 따라서 과거 버전으로 생성된 해시도
 * 올바른 비밀번호면 검증에 성공한다. 단, 이 클래스는 해시 생성·검증만 담당하며 구버전 해시를 최신 버전으로
 * 재해시(마이그레이션)하지는 않는다.
 */
public class Argon2idPasswordEncoder implements PasswordEncoder {

  /** salt 길이(바이트). KT 기준(≥16byte)을 충족한다. */
  private static final int SALT_LENGTH = 16;

  /** 해시 출력 길이(바이트). 32바이트=256비트로 KT 기준(≥256bit)을 충족한다. */
  private static final int HASH_LENGTH = 32;

  /** Argon2 1.0 버전 식별자(0x10=16). 과거 생성된 해시 검증을 위해 허용한다. */
  private static final int ARGON2_VERSION_10 = Argon2Parameters.ARGON2_VERSION_10;

  /** Argon2 1.3 버전 식별자(0x13=19). PHC 문자열의 {@code v=19}에 해당한다. */
  private static final int ARGON2_VERSION_13 = Argon2Parameters.ARGON2_VERSION_13;

  /** 신규 인코딩에 사용하는 버전. 항상 최신(1.3=v=19). */
  private static final int GENERATE_VERSION = ARGON2_VERSION_13;

  /**
   * 검증 시 신뢰할 수 없는 PHC 문자열의 과도한 메모리 파라미터로 인한 자원 고갈(OOM)을 막기 위한 상한(KiB).
   * 1 GiB. 비밀번호 해시에 필요한 메모리는 통상 수십 MiB 수준이므로 정상 값은 이 한도를 넘지 않는다.
   */
  private static final int MAX_MEMORY_KB = 1 << 20;

  /** OWASP 권장 기본 메모리 비용(KiB). 47104 KiB = 46 MiB (OWASP 옵션 A). */
  public static final int DEFAULT_MEMORY_KB = 47104;

  /** OWASP 권장 기본 반복 횟수(time cost). 메모리 46MiB와 짝을 이루는 t=1. */
  public static final int DEFAULT_ITERATIONS = 1;

  /** OWASP 권장 기본 병렬도(lane 수). */
  public static final int DEFAULT_PARALLELISM = 1;

  /**
   * {@code $argon2id$v=<n>$m=<n>,t=<n>,p=<n>$<saltB64>$<hashB64>} 형태의 표준 PHC 포맷.
   * salt/hash는 패딩 없는 base64.
   */
  private static final Pattern PHC_PATTERN =
      Pattern.compile(
          "^\\$argon2id\\$v=(\\d+)\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$([A-Za-z0-9+/]+)\\$([A-Za-z0-9+/]+)$");

  private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder().withoutPadding();
  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private final int memoryKb;
  private final int iterations;
  private final int parallelism;
  private final SecureRandom secureRandom = new SecureRandom();

  /** OWASP 권장 기본 파라미터로 생성한다. */
  public Argon2idPasswordEncoder() {
    this(DEFAULT_MEMORY_KB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
  }

  /**
   * 지정한 파라미터로 생성한다.
   *
   * @param memoryKb 메모리 비용(KiB), 양수
   * @param iterations 반복 횟수(time cost), 양수
   * @param parallelism 병렬도(lane 수), 양수
   * @throws IllegalArgumentException 파라미터가 1 미만인 경우
   */
  public Argon2idPasswordEncoder(int memoryKb, int iterations, int parallelism) {
    if (memoryKb < 1) {
      throw new IllegalArgumentException("memoryKb must be >= 1: " + memoryKb);
    }
    if (iterations < 1) {
      throw new IllegalArgumentException("iterations must be >= 1: " + iterations);
    }
    if (parallelism < 1) {
      throw new IllegalArgumentException("parallelism must be >= 1: " + parallelism);
    }
    this.memoryKb = memoryKb;
    this.iterations = iterations;
    this.parallelism = parallelism;
  }

  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword == null) {
      throw new IllegalArgumentException("rawPassword must not be null");
    }
    byte[] salt = new byte[SALT_LENGTH];
    secureRandom.nextBytes(salt);
    byte[] hash =
        hash(rawPassword, salt, GENERATE_VERSION, memoryKb, iterations, parallelism, HASH_LENGTH);
    return format(salt, hash, GENERATE_VERSION, memoryKb, iterations, parallelism);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null) {
      return false;
    }
    Matcher matcher = matchPhc(encodedPassword);
    if (matcher == null) {
      return false;
    }
    try {
      int version = Integer.parseInt(matcher.group(1));
      // 알려진 Argon2 버전(1.0/1.3)만 검증 대상. 저장된 버전 그대로 재계산해야 일치한다.
      if (version != ARGON2_VERSION_10 && version != ARGON2_VERSION_13) {
        return false;
      }
      int storedMemory = Integer.parseInt(matcher.group(2));
      // 신뢰할 수 없는 입력의 거대 메모리 값으로 인한 OOM 방지
      if (storedMemory > MAX_MEMORY_KB) {
        return false;
      }
      int storedIterations = Integer.parseInt(matcher.group(3));
      int storedParallelism = Integer.parseInt(matcher.group(4));
      byte[] storedSalt = BASE64_DECODER.decode(matcher.group(5));
      byte[] storedHash = BASE64_DECODER.decode(matcher.group(6));

      byte[] computed =
          hash(
              rawPassword,
              storedSalt,
              version,
              storedMemory,
              storedIterations,
              storedParallelism,
              storedHash.length);
      // 상수 시간 비교로 타이밍 공격 방지
      return MessageDigest.isEqual(storedHash, computed);
    } catch (RuntimeException e) {
      // 패턴은 통과해도 base64 디코딩·파라미터 파싱에 실패하면 불일치로 간주
      return false;
    }
  }

  @Override
  public boolean upgradeNeeded(String encodedPassword) {
    Matcher matcher = matchPhc(encodedPassword);
    if (matcher == null) {
      // 레거시·null·형식 불일치(bcrypt, ARIA 등)는 모두 재해시 대상
      return true;
    }
    int storedMemory = Integer.parseInt(matcher.group(2));
    int storedIterations = Integer.parseInt(matcher.group(3));
    int storedParallelism = Integer.parseInt(matcher.group(4));
    // 저장된 비용 파라미터 중 하나라도 현재 정책보다 낮으면 재해시 필요
    return storedMemory < memoryKb
        || storedIterations < iterations
        || storedParallelism < parallelism;
  }

  /**
   * 문자열이 표준 Argon2id PHC 포맷인지 확인한다.
   *
   * @param value 검사할 문자열
   * @return Argon2id 포맷이면 true
   */
  public static boolean isArgon2idHash(String value) {
    return matchPhc(value) != null;
  }

  /** 설정된 메모리 비용(KiB)을 반환한다. */
  public int getMemoryKb() {
    return memoryKb;
  }

  /** 설정된 반복 횟수를 반환한다. */
  public int getIterations() {
    return iterations;
  }

  /** 설정된 병렬도를 반환한다. */
  public int getParallelism() {
    return parallelism;
  }

  /** 매칭에 성공하면 {@link Matcher}를, 아니면 null을 반환한다. */
  private static Matcher matchPhc(String value) {
    if (value == null) {
      return null;
    }
    Matcher matcher = PHC_PATTERN.matcher(value);
    return matcher.matches() ? matcher : null;
  }

  private static byte[] hash(
      CharSequence rawPassword,
      byte[] salt,
      int version,
      int memoryKb,
      int iterations,
      int parallelism,
      int outputLength) {
    Argon2Parameters params =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(version)
            .withMemoryAsKB(memoryKb)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build();

    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(params);

    byte[] output = new byte[outputLength];
    byte[] passwordBytes = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
    generator.generateBytes(passwordBytes, output);
    return output;
  }

  private static String format(
      byte[] salt, byte[] hash, int version, int memoryKb, int iterations, int parallelism) {
    return "$argon2id$v="
        + version
        + "$m="
        + memoryKb
        + ",t="
        + iterations
        + ",p="
        + parallelism
        + "$"
        + BASE64_ENCODER.encodeToString(salt)
        + "$"
        + BASE64_ENCODER.encodeToString(hash);
  }
}
