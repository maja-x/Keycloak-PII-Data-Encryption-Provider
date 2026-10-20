/*
 * PII Data Encryption for Keycloak
 * Copyright (c) 2026 Makara Mas
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A PII value protected by envelope encryption: the ciphertext plus the data
 * key (DEK) that was used to encrypt it, in its wrapped (encrypted by the
 * master key / KEK) form, plus the optional blind index.
 *
 * <p>
 * The wrapped data key embeds its key version in the same way the keyring does
 * ({@code v1:<base64>}), which is what makes key rotation possible: a value can
 * always be decrypted as long as the key version it references is still part of
 * the keyring, and the data key can be re-wrapped with a newer master key
 * without touching the ciphertext.</p>
 *
 * @author Makara Mas <support@makaramas.com>
 */
public final class ProtectedValue {

    /**
     * Prefix of every protected value stored by this provider. Shared with the
     * ciphertext format of previous versions so that old values are still
     * recognized and can be migrated.
     */
    public static final String CIPHERTEXT_PREFIX = "$$$";

    /**
     * Version of the serialized layout. Bumping this is only necessary when the
     * layout itself changes, not when keys are rotated.
     */
    public static final String ENVELOPE_VERSION = "v1";

    private static final Pattern KEY_VERSION = Pattern.compile("^v\\d+$");
    private static final Pattern ENVELOPE = Pattern.compile("^v\\d+:");

    private final String dataKey;
    private final String ciphertext;
    private final String index;

    /**
     * @param dataKey The wrapped data key ({@code <key version>:<base64>})
     * @param ciphertext The encrypted value (Base64)
     * @param index The blind index of the plaintext value, may be null
     */
    public ProtectedValue(String dataKey, String ciphertext, String index) {
        this.dataKey = Objects.requireNonNull(dataKey, "dataKey");
        this.ciphertext = Objects.requireNonNull(ciphertext, "ciphertext");
        this.index = index;
        String version = keyVersionOf(dataKey);
        if (!KEY_VERSION.matcher(version).matches()) {
            throw new IllegalArgumentException("Invalid data key: missing key version prefix (expected " + KeyRing.LEGACY_VERSION + "|<version>:<base64>)");
        }
    }

    /**
     * Parses a value produced by {@link #serialize()}.
     *
     * @param value The stored value
     * @return The ProtectedValue, or null if the value is not in the current
     * envelope format (e.g. null, plaintext, or ciphertext from version 1.x)
     */
    public static ProtectedValue parse(String value) {
        if (value == null || !value.startsWith(CIPHERTEXT_PREFIX)) {
            return null;
        }
        String body = value.substring(CIPHERTEXT_PREFIX.length());
        if (!ENVELOPE.matcher(body).find()) {
            return null;
        }
        String[] parts = body.split(":", 4);
        if (parts.length != 4 || !ENVELOPE_VERSION.equals(parts[0])) {
            return null;
        }
        String dataKey = parts[1] + ":" + parts[2];
        String ciphertext = parts[3];
        if (ciphertext.isEmpty()) {
            return null;
        }
        return new ProtectedValue(dataKey, ciphertext, null);
    }

    /**
     * Checks whether the passed value is a protected (encrypted) value in any
     * supported format.
     *
     * @param value The value to check
     * @return true if the value is protected
     */
    public static boolean isProtected(String value) {
        return value != null && value.startsWith(CIPHERTEXT_PREFIX);
    }

    /**
     * @return The wrapped data key, including its key version
     */
    public String getDataKey() {
        return dataKey;
    }

    /**
     * @return The version of the master key that wrapped the data key
     */
    public String getKeyVersion() {
        return keyVersionOf(dataKey);
    }

    /**
     * @return The encrypted value
     */
    public String getCiphertext() {
        return ciphertext;
    }

    /**
     * @return The blind index of the plaintext value, may be null
     */
    public String getIndex() {
        return index;
    }

    /**
     * @param index The blind index to attach
     * @return A copy of this value with the passed blind index
     */
    public ProtectedValue withIndex(String index) {
        return new ProtectedValue(dataKey, ciphertext, index);
    }

    /**
     * @param dataKey The wrapped data key to use
     * @return A copy of this value with the passed wrapped data key
     */
    public ProtectedValue withDataKey(String dataKey) {
        return new ProtectedValue(dataKey, ciphertext, index);
    }

    /**
     * Serializes this value into the single column representation used by the
     * provider: {@code $$$v1:<key version>:<wrapped data key>:<ciphertext>}.
     *
     * @return The serialized value
     */
    public String serialize() {
        return CIPHERTEXT_PREFIX + ENVELOPE_VERSION + ":" + dataKey + ":" + ciphertext;
    }

    private static String keyVersionOf(String dataKey) {
        int separator = dataKey.indexOf(':');
        return separator < 0 ? dataKey : dataKey.substring(0, separator);
    }

    @Override
    public String toString() {
        return serialize();
    }

}
