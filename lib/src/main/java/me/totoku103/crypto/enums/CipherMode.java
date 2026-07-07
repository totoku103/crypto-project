package me.totoku103.crypto.enums;

/** 블록 암호 운영 모드 */
public enum CipherMode {
  /** ECB. IV 없이 동작하며 같은 평문이면 늘 같은 암호문이 나온다. */
  ECB,
  /** CBC. 16바이트 IV를 사용한다. */
  CBC
}
