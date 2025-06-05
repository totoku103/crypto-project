# Crypto Project

`me.totoku103.crypto.kisa.sha3.sha3` 패키지는 순수 자바 SHA-3 구현을 담고 있습니다.
`Sha3Optimized` 클래스는 JDK `MessageDigest`를 사용해 속도를 높였습니다.

## Tests

테스트는 `test` 패키지에 있습니다. 두 구현이 같은 값을 내는지 확인하며
한글과 이모지를 포함한 다양한 문자열을 사용합니다. 또한 SHA3의 네 가지
비트 길이(224, 256, 384, 512)에 대해 결과가 일치하는지 검증합니다.
