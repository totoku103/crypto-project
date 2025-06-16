package me.totoku103.crypto.kisa.aria.mode;

import me.totoku103.crypto.utils.ConvertUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class AriaModesTest {
    private static final byte[] KEY = ConvertUtils.fromHex("00112233445566778899aabbccddeeff0011223344556677");
    private static final byte[] IV = ConvertUtils.fromHex("0f1e2d3c4b5a69788796a5b4");
    private static final byte[] AAD = "header".getBytes();

    @Test
    @DisplayName("CTR mode round-trip")
    void ctrRoundTrip() {
        byte[] data = "hello aria ctr".getBytes();
        byte[] enc = AriaModes.processCtr(KEY, IV, data);
        byte[] dec = AriaModes.processCtr(KEY, IV, enc);
        assertArrayEquals(data, dec);
    }

    @Test
    @DisplayName("CFB mode round-trip")
    void cfbRoundTrip() {
        byte[] data = "hello aria cfb".getBytes();
        byte[] enc = AriaModes.encryptCfb(KEY, IV, data);
        byte[] dec = AriaModes.decryptCfb(KEY, IV, enc);
        assertArrayEquals(data, dec);
    }

    @Test
    @DisplayName("OFB mode round-trip")
    void ofbRoundTrip() {
        byte[] data = "hello aria ofb".getBytes();
        byte[] enc = AriaModes.processOfb(KEY, IV, data);
        byte[] dec = AriaModes.processOfb(KEY, IV, enc);
        assertArrayEquals(data, dec);
    }

    @Test
    @DisplayName("GCM mode round-trip")
    void gcmRoundTrip() throws InvalidCipherTextException {
        byte[] data = "gcm test data".getBytes();
        var res = AriaModes.encryptGcm(KEY, IV, AAD, data, 128);
        byte[] plain = AriaModes.decryptGcm(KEY, IV, AAD, res.ciphertext, res.tag);
        assertArrayEquals(data, plain);
    }

    @Test
    @DisplayName("CCM mode round-trip")
    void ccmRoundTrip() throws InvalidCipherTextException {
        byte[] data = "ccm test data".getBytes();
        var res = AriaModes.encryptCcm(KEY, IV, AAD, data, 128);
        byte[] plain = AriaModes.decryptCcm(KEY, IV, AAD, res.ciphertext, res.tag);
        assertArrayEquals(data, plain);
    }

    @Test
    @DisplayName("CMAC computation")
    void cmacComputation() {
        byte[] data = "message".getBytes();
        byte[] mac1 = AriaModes.cmac(KEY, data);
        byte[] mac2 = AriaModes.cmac(KEY, data);
        assertArrayEquals(mac1, mac2);
    }
}
