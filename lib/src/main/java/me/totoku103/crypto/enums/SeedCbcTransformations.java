package me.totoku103.crypto.enums;

public enum SeedCbcTransformations {
    SEED_CBC_NO_PADDING("SEED/CBC/NoPadding"),
    SEED_CBC_PKCS7_PADDING("SEED/CBC/PKCS7Padding");

    private final String value;

    SeedCbcTransformations(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
