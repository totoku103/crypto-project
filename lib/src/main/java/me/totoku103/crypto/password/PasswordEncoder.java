package me.totoku103.crypto.password;

/**
 * 비밀번호 단방향 해시·검증을 위한 인터페이스.
 *
 * <p>양방향 블록 암호({@link me.totoku103.crypto.core.BlockCipher})와 달리 복호화를 제공하지 않으며,
 * 원문을 알 수 없는 상태에서 일치 여부만 검증한다. 구현체는 사용자별 랜덤 salt를 자동 생성하여
 * 결과 문자열에 포함(self-contained)하므로, 같은 원문이라도 매번 다른 인코딩 결과를 반환한다.
 */
public interface PasswordEncoder {

  /**
   * 원문 비밀번호를 단방향 해시로 인코딩한다.
   *
   * <p>호출할 때마다 새로운 랜덤 salt가 적용되므로 동일한 원문이라도 결과가 매번 달라진다.
   *
   * @param rawPassword 원문 비밀번호 (null 불가)
   * @return salt가 포함된 인코딩 문자열
   */
  String encode(CharSequence rawPassword);

  /**
   * 원문 비밀번호가 인코딩된 값과 일치하는지 검증한다.
   *
   * @param rawPassword 검증할 원문 비밀번호
   * @param encodedPassword 저장된 인코딩 문자열
   * @return 일치하면 true, 불일치하거나 인코딩 형식이 올바르지 않으면 false
   */
  boolean matches(CharSequence rawPassword, String encodedPassword);

  /**
   * 저장된 인코딩 값이 현재 정책(알고리즘·강도)으로 재해시되어야 하는지 판단한다.
   *
   * <p>점진적 마이그레이션 전략에서 사용한다. 예를 들어 레거시 형식이거나 work factor가
   * 현재 설정보다 낮은 경우 true를 반환하여 로그인 성공 시점에 재해시를 유도한다.
   *
   * @param encodedPassword 저장된 인코딩 문자열
   * @return 재해시가 필요하면 true
   */
  boolean upgradeNeeded(String encodedPassword);
}
