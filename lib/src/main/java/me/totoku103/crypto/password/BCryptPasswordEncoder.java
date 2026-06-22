package me.totoku103.crypto.password;

import java.security.SecureRandom;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/**
 * bcrypt(OpenBSD 표준 포맷) 기반 {@link PasswordEncoder} 구현.
 *
 * <p>BouncyCastle {@link OpenBSDBCrypt}를 사용하며, 인코딩 시 {@link SecureRandom}으로 16바이트 랜덤
 * salt를 생성한다. 결과는 {@code $2y$<cost>$<salt><hash>} 형태의 60자 문자열로, salt가 포함되어
 * 별도 컬럼 없이 검증할 수 있다.
 *
 * <p><b>제약:</b> bcrypt는 입력 비밀번호의 앞 72바이트만 사용한다(이후 바이트는 무시). 72바이트를 초과하는
 * 비밀번호 정책을 사용하는 경우 사전 해시(pre-hash) 등 별도 대응이 필요하다.
 */
public class BCryptPasswordEncoder implements PasswordEncoder {

  /** bcrypt salt 길이(바이트). KT 기준(≥16byte)을 충족한다. */
  private static final int SALT_LENGTH = 16;

  /** OpenBSD bcrypt 버전 식별자. */
  private static final String VERSION = "2y";

  /** bcrypt가 허용하는 work factor(cost) 범위. */
  private static final int MIN_COST = 4;
  private static final int MAX_COST = 31;

  /** 기본 work factor. 로그인당 CPU 비용과 보안 강도의 균형점. */
  public static final int DEFAULT_COST = 12;

  /** {@code $2a$/$2b$/$2y$<2자리 cost>$} 로 시작하는 60자 표준 bcrypt 포맷. */
  private static final Pattern BCRYPT_PATTERN = Pattern.compile("^\\$2[aby]\\$(\\d{2})\\$.{53}$");

  private final int cost;
  private final SecureRandom secureRandom = new SecureRandom();

  /** 기본 work factor({@value #DEFAULT_COST})로 생성한다. */
  public BCryptPasswordEncoder() {
    this(DEFAULT_COST);
  }

  /**
   * 지정한 work factor로 생성한다.
   *
   * @param cost bcrypt work factor (4~31)
   * @throws IllegalArgumentException cost가 허용 범위를 벗어난 경우
   */
  public BCryptPasswordEncoder(int cost) {
    if (cost < MIN_COST || cost > MAX_COST) {
      throw new IllegalArgumentException(
          "cost must be between " + MIN_COST + " and " + MAX_COST + ": " + cost);
    }
    this.cost = cost;
  }

  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword == null) {
      throw new IllegalArgumentException("rawPassword must not be null");
    }
    byte[] salt = new byte[SALT_LENGTH];
    secureRandom.nextBytes(salt);
    return OpenBSDBCrypt.generate(VERSION, toChars(rawPassword), salt, cost);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null || !isBCryptHash(encodedPassword)) {
      return false;
    }
    try {
      return OpenBSDBCrypt.checkPassword(encodedPassword, toChars(rawPassword));
    } catch (RuntimeException e) {
      // 형식이 표준 패턴을 통과해도 내부 파싱에 실패하면 불일치로 간주
      return false;
    }
  }

  @Override
  public boolean upgradeNeeded(String encodedPassword) {
    if (!isBCryptHash(encodedPassword)) {
      // 레거시(ARIA 등)·null·형식 불일치는 모두 재해시 대상
      return true;
    }
    return parseCost(encodedPassword) < cost;
  }

  /**
   * 문자열이 표준 bcrypt 해시 포맷인지 확인한다.
   *
   * @param value 검사할 문자열
   * @return bcrypt 포맷이면 true
   */
  public static boolean isBCryptHash(String value) {
    return value != null && BCRYPT_PATTERN.matcher(value).matches();
  }

  /** 설정된 work factor를 반환한다. */
  public int getCost() {
    return cost;
  }

  private static int parseCost(String bcryptHash) {
    // $2y$12$.... → "12"
    return Integer.parseInt(bcryptHash.substring(4, 6));
  }

  private static char[] toChars(CharSequence rawPassword) {
    return rawPassword.toString().toCharArray();
  }
}
