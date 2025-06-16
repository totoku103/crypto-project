package me.totoku103.crypto.kisa.aria.mode;

import me.totoku103.crypto.kisa.aria.AriaBcBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import me.totoku103.crypto.utils.ConvertUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AriaModeVectorsTest {
    private static final byte[] KEY = ConvertUtils.fromHex("00112233445566778899aabbccddeeff");
    private static final byte[] IV = ConvertUtils.fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    private static final byte[] PLAINTEXT = ConvertUtils.fromHex(
            "11111111aaaaaaaa11111111bbbbbbbb"
            + "11111111cccccccc11111111dddddddd"
            + "22222222aaaaaaaa22222222bbbbbbbb"
            + "22222222cccccccc22222222dddddddd"
            + "33333333aaaaaaaa33333333bbbbbbbb"
            + "33333333cccccccc33333333dddddddd"
            + "44444444aaaaaaaa44444444bbbbbbbb"
            + "44444444cccccccc44444444dddddddd"
            + "55555555aaaaaaaa55555555bbbbbbbb"
            + "55555555cccccccc55555555dddddddd");

    private static final byte[] CT_ECB = ConvertUtils.fromHex(
            "c6ecd08e22c30abdb215cf74e2075e6e"
            + "29ccaac63448708d331b2f816c51b17d"
            + "9e133d1528dbf0af5787c7f3a3f5c2bf"
            + "6b6f345907a3055612ce072ff54de7d7"
            + "88424da6e8ccfe8172b391be49935416"
            + "5665ba7864917000a6eeb2ecb4a698ed"
            + "fc7887e7f556377614ab0a282293e6d8"
            + "84dbb84206cdb16ed1754e77a1f243fd"
            + "086953f752cc1e46c7c794ae85537dca"
            + "ec8dd721f55c93b6edfe2adea43873e8");

    private static final byte[] CT_CBC = ConvertUtils.fromHex(
            "49d61860b14909109cef0d22a9268134"
            + "fadf9fb23151e9645fba75018bdb1538"
            + "b53334634bbf7d4cd4b5377033060c15"
            + "5fe3948ca75de1031e1d85619e0ad61e"
            + "b419a866b3c2dbfd10a4ed18b22149f7"
            + "5897f0b8668b0c1c542c687778835fb7"
            + "cd46e45f85eaa7072437dd9fa6793d6f"
            + "8d4ccefc4eb1ac641ac1bd30b18c6d64"
            + "c49bca137eb21c2e04da62712ca2b4f5"
            + "40c57112c38791852cfac7a5d19ed83a");

    private static final byte[] CT_CFB128 = ConvertUtils.fromHex(
            "3720e53ba7d615383406b09f0a05a200c07c21e6370f413a5d132500a6828501"
            + "7c61b434c7b7ca9685a51071861e4d4bb873b599b479e2d573dddeafba89f812"
            + "ac6a9e44d554078eb3be94839db4b33da3f59c063123a7ef6f20e10579fa4fd2"
            + "39100ca73b52d4fcafeadee73f139f78f9b7614c2b3b9dbe010f87db06a89a94"
            + "35f79ce8121431371f4e87b984e0230c22a6dacb32fc42dcc6accef33285bf11");

    private static final byte[] CT_CFB64 = ConvertUtils.fromHex("3720e53ba7d61538595743814e943acc821a056e3c5fdb10eeaed5e2de03e5bb" 
            + "60f528f9bad9a267e98da2237054ef9060564ec489a19533ab0fad70fe044b43" 
            + "a3c0579da9def9a26e428dbdac645ebfaa94bce08852cd1f3538d57ea3fa9f1a" 
            + "3723846f2287627c94b15a06136b6683504c9860e2ad9de7d96f310083a4aa25" 
            + "10f2f67b04fea774801cae4f0d0a6bad467b6c3a90e019a7c67ad24493bbdf46");

    private static final byte[] CT_CFB16 = ConvertUtils.fromHex(
            "37203a2ac0bff752e4bab589f4ad3ea82277a6ff4b5841ad92f4b8e5d1aa6e8"
            + "a95bfde0ad6ec9f7cc711e4f67212d0afe92497463054becd398e26ee39388be"
            + "725fa38c33ad07cfada2be83a770a034e969b29b9c6d3523e148d0695f2338f9"
            + "5ff2ec01ab69fcf8f9c77fcb71691ceb830fd166d05deddb2dba6a38eff5bf14"
            + "2b1abfb0fe8b520f3a691a8a4f87e24a6e857beca437e66abcc4a5bf43d6d6bfe");

    private static final byte[] CT_CFB8 = ConvertUtils.fromHex(
            "373c8f6a965599ec785cc8f8149f6c81b632ccb8e0c6eb6a9707ae52c59257a4"
            + "1f94701c1096933127a90195ed0c8e98690547572423bb45c3d70e4a18ee56b9"
            + "67c10e000ba4df5fba7c404134a343d8375d04b151d161ef83417fe1748447d3"
            + "0a6723c406733df7d18aa39a20752d2381942e244811bb97f72eae446b1815aa"
            + "690cd1b1adcbd007c0088ecdc91cb2e2caf0e11e72459878137eea64ac62a9a1");

    private static final byte[] CT_OFB128 = ConvertUtils.fromHex(
            "3720e53ba7d615383406b09f0a05a2000063063f0560083483faeb041c8adece"
            + "f30cf80cefb002a0d280759168ec01db3d49f61aced260bd43eec0a2731730ee"
            + "c6fa4f2304319cf8ccac2d7be7833e4f8ae6ce967012c1c6badc5d28e7e4144f"
            + "6bf5cebe01253ee202afce4bc61f28dec069a6f16f6c8a7dd2afae44148f6ff4"
            + "d0029d5c607b5fa6b8c8a6301cde5c7033565cd0b8f0974ab490b236197ba04a");

    private static final byte[] CT_OFB64 = ConvertUtils.fromHex("3720e53ba7d615388cef8367cafc4c789bd7112f72e158784c5e3489035cbb7f3c6c02d2e3cd0af54c42241d8d57aceeeac6c1af1505bb2576f373794e4040345b6e4ab275f7a9539fc47544f0c804a86625cb846c88df0595d410328bef4463555d7d8b97e0f73f9af61b834d9937b330901a1639df1d4514b55829d878b81f7cacd832ff8027a44864f2e3e937427f9adb8675e9cb9f01a47eb94732669f1d");

    private static final byte[] CT_OFB16 = ConvertUtils.fromHex("372096a36007760d97f7794b0c3f2e21c693cacc851a7f62d95adc7c720ae40d27a5a60d701c6a4191c9068eca703eb7ef3f1f25ca35892a3c865787773879b83942d501a36a525621758142f9c74926577ccd2ad492f77450a0ceeb7c2f18cf4b132ac37b1202b670e7011de3a5779b884ae74612c249f8c9ce6a9042fdf3f54e4f621b24aa3c61506c4f50b9d091d59dd5252a0c1e8fc6f58326b022ee9f4d");

    private static final byte[] CT_OFB8 = ConvertUtils.fromHex("37252849717c77a65287c93cd95af701471f14c11017fd040a0e71058e262f37f71ee11a82e367ab53a749215dc4b0a06298c996dbb2d43e6682f885b1253c423b6cec70ff98074f9bb55a8268b8bc0b922e644daaa2719f3f251c146cb9b7b633a64240f3a9fba437c8ff14f966bbd45ce7c9b06cf1507919a226d4b416e15ff3b0e6ce2e6658b7bbed6d066fe71cdb900cd3ec929f0064f45fd8e6b8b46519");

    private static final byte[] CT_CTR = ConvertUtils.fromHex("3720e53ba7d615383406b09f0a05a2001673032f1d03d982e5671311789b6f4ab461748f2f56718727d7a084f1499d101c9e2d05a74a5eeb00c27c811490ae5381e9e3b57b24a361adfd3706cd39c265bdbfb65d1c84ef37e4f6b8b58ac6dd628ae47c6115c6a581fb66706735080b4c336190a6e1e0d43e79ee0dad09faa9270dc680c2197f4cd164f9e92985dbcab8df1eefc2069f96c1825fe5fd561f0d20");

    @Test
    @DisplayName("ECB 모드 공식 테스트 벡터와 일치하는지 검증")
    void ecbVectorShouldMatchReference() {
        BlockCipher engine = new AriaBcBlockCipher();
        engine.init(true, new KeyParameter(KEY));
        byte[] out = new byte[PLAINTEXT.length];
        for (int i = 0; i < PLAINTEXT.length; i += engine.getBlockSize()) {
            engine.processBlock(PLAINTEXT, i, out, i);
        }
        assertArrayEquals(CT_ECB, out);

        engine.init(false, new KeyParameter(KEY));
        byte[] dec = new byte[out.length];
        for (int i = 0; i < out.length; i += engine.getBlockSize()) {
            engine.processBlock(out, i, dec, i);
        }
        assertArrayEquals(PLAINTEXT, dec);
    }

    @Test
    @DisplayName("CBC 모드 공식 테스트 벡터와 일치하는지 검증")
    void cbcVectorShouldMatchReference() {
        byte[] cipher = AriaModes.encryptCbc(KEY, IV, PLAINTEXT);
        assertArrayEquals(CT_CBC, cipher);
        byte[] plain = AriaModes.decryptCbc(KEY, IV, cipher);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("CFB-128 모드 테스트 벡터와 결과가 동일해야 한다")
    void cfb128VectorShouldMatchReference() {
        byte[] cipher = AriaModes.encryptCfb(KEY, IV, PLAINTEXT, 128);
        assertArrayEquals(CT_CFB128, cipher);
        byte[] plain = AriaModes.decryptCfb(KEY, IV, cipher, 128);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("CFB-64 모드 테스트 벡터와 결과가 동일해야 한다")
    void cfb64VectorShouldMatchReference() {
        byte[] cipher = AriaModes.encryptCfb(KEY, IV, PLAINTEXT, 64);
        assertArrayEquals(CT_CFB64, cipher);
        byte[] plain = AriaModes.decryptCfb(KEY, IV, cipher, 64);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("CFB-16 모드 테스트 벡터와 결과가 동일해야 한다")
    void cfb16VectorShouldMatchReference() {
        byte[] cipher = AriaModes.encryptCfb(KEY, IV, PLAINTEXT, 16);
        assertArrayEquals(CT_CFB16, cipher);
        byte[] plain = AriaModes.decryptCfb(KEY, IV, cipher, 16);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("CFB-8 모드 테스트 벡터와 결과가 동일해야 한다")
    void cfb8VectorShouldMatchReference() {
        byte[] cipher = AriaModes.encryptCfb(KEY, IV, PLAINTEXT, 8);
        assertArrayEquals(CT_CFB8, cipher);
        byte[] plain = AriaModes.decryptCfb(KEY, IV, cipher, 8);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("OFB-128 모드 테스트 벡터와 결과가 동일해야 한다")
    void ofb128VectorShouldMatchReference() {
        byte[] cipher = AriaModes.processOfb(KEY, IV, PLAINTEXT, 128);
        assertArrayEquals(CT_OFB128, cipher);
        byte[] plain = AriaModes.processOfb(KEY, IV, cipher, 128);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("OFB-64 모드 테스트 벡터와 결과가 동일해야 한다")
    void ofb64VectorShouldMatchReference() {
        byte[] cipher = AriaModes.processOfb(KEY, IV, PLAINTEXT, 64);
        assertArrayEquals(CT_OFB64, cipher);
        byte[] plain = AriaModes.processOfb(KEY, IV, cipher, 64);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("OFB-16 모드 테스트 벡터와 결과가 동일해야 한다")
    void ofb16VectorShouldMatchReference() {
        byte[] cipher = AriaModes.processOfb(KEY, IV, PLAINTEXT, 16);
        assertArrayEquals(CT_OFB16, cipher);
        byte[] plain = AriaModes.processOfb(KEY, IV, cipher, 16);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("OFB-8 모드 테스트 벡터와 결과가 동일해야 한다")
    void ofb8VectorShouldMatchReference() {
        byte[] cipher = AriaModes.processOfb(KEY, IV, PLAINTEXT, 8);
        assertArrayEquals(CT_OFB8, cipher);
        byte[] plain = AriaModes.processOfb(KEY, IV, cipher, 8);
        assertArrayEquals(PLAINTEXT, plain);
    }

    @Test
    @DisplayName("CTR 모드 테스트 벡터와 결과가 동일해야 한다")
    void ctrVectorShouldMatchReference() {
        byte[] cipher = AriaModes.processCtr(KEY, IV, PLAINTEXT);
        assertArrayEquals(CT_CTR, cipher);
        byte[] plain = AriaModes.processCtr(KEY, IV, cipher);
        assertArrayEquals(PLAINTEXT, plain);
    }
}
