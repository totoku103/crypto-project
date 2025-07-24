package me.totoku103.crypto.kisa.hmac;

import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KISA_HMACTest_2 {

    @Test
    public void testMainCode() {
        final byte[] keyBytes = HexConverter.toBytes("4DC5377E40EA0E6877A8EAD188CCB5075E284A8D398993B7F6E9EE7391E5D66A");
        final byte[] messageBytes = HexConverter.toBytes("E871BF48C1CA41570FAC795371C6AD7AFC6B2EE23A8A830F72E0C3C52A6C431BEB2371D144E600E311B1465EFE15E27346E8A1CAC13BA3191D8CB9F46B3D12E7DE4517C2D0269334061F179B35A29D1BC5086BEDD4843AFA7E5598A95C408BF54A3E77C26E724171765DB5B220552599003353F57E4D92DD1EA4278B045EF56E");
        final byte[] ctBytes = HexConverter.toBytes("63C6510B16E8E4272F295A219606AC49F0E764720B3BB7405802F0B31F258A2D");

        final byte[] output = new byte[32];

        KISA_HMAC.HMAC_SHA256_Transform(output, keyBytes, keyBytes.length, messageBytes, messageBytes.length);
        final String s = HexConverter.fromBytes(output);
        Utils.print_hex("output", output, output.length);
        Assertions.assertArrayEquals(ctBytes, output);
    }

}