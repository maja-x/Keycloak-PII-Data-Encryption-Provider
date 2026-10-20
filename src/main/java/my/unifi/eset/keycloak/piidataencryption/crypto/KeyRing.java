/*
 * Copyright (C) 2026 Makara Mas <support@makaramas.com>
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Ordered collection of versioned keys. Both the master keys (KEK) that wrap
 * the data keys (DEK) and the peppers that feed the blind index are configured
 * as a keyring in the format {@code v1:<key>,v2:<key>}.
 *
 * <p>
 * Every entry is prefixed with its version so old keys can be kept around while
 * new values are protected with the active one. A key without a version prefix
 * is assigned {@link #LEGACY_VERSION} and its raw bytes are used as-is, which
 * keeps ciphertext produced by previous versions of this provider decryptable
 * (those versions used the raw {@code KC_PII_ENCKEY} value as the AES key).</p>
 *
 * @author Makara Mas <support@makaramas.com>
 */
public final class KeyRing {

    /**
     * Version assigned to a key that is configured without a {@code vN:}
     * prefix.
     */
    public static final String LEGACY_VERSION = "v0";

    /**
     * Length of a generated key in bytes (AES-256).
     */
    public static final int KEY_LENGTH = 32;

    private static final Pattern VERSION_PREFIX = Pattern.compile("^v\\d+$");
    private static final Pattern KEY_VERSION = Pattern.compile("^v\\d+$");
    private static final int[] VALID_KEY_LENGTHS = {16, 24, 32};
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, byte[]> keys;
    private final String activeVersion;
    private final String source;

    private KeyRing(Map<String, byte[]> keys, String activeVersion, String source) {
        this.keys = Collections.unmodifiableMap(keys);
        this.activeVersion = activeVersion;
        this.source = source;
    }

    /**
     * Parses a keyring configuration string such as
     * {@code v1:<base64 key>,v2:<base64 key>}.
     *
     * @param raw The configuration value
     * @param activeVersion The version of the key to use for new
     * encryptions/derivations, or null/blank to use the last configured key
     * @param source Name of the configuration source, used in error messages
     * @return The parsed KeyRing
     * @throws IllegalArgumentException when the configuration is missing,
     * malformed or does not contain the active version
     */
    public static KeyRing parse(String raw, String activeVersion, String source) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("Encryption key is not configured. Set the " + source + " environment variable using the format v1:<base64 key>.");
        }
        Map<String, byte[]> parsed = new LinkedHashMap<>();
        boolean legacyEntryPresent = false;
        for (String entry : raw.split(",")) {
            String candidate = entry.trim();
            if (candidate.isEmpty()) {
                continue;
            }
            int separator = candidate.indexOf(':');
            boolean versioned = separator > 0 && VERSION_PREFIX.matcher(candidate.substring(0, separator).trim()).matches();
            String version;
            byte[] material;
            if (versioned) {
                version = candidate.substring(0, separator).trim();
                material = decodeMaterial(candidate.substring(separator + 1).trim(), version, source);
            } else {
                if (legacyEntryPresent) {
                    throw new IllegalArgumentException("Only one key without version prefix is allowed in " + source + ". Prefix additional keys with their version, e.g. v2:<base64 key>.");
                }
                legacyEntryPresent = true;
                version = LEGACY_VERSION;
                material = decodeLegacyMaterial(candidate, source);
            }
            if (parsed.containsKey(version)) {
                throw new IllegalArgumentException("Duplicate key version " + version + " in " + source + ".");
            }
            parsed.put(version, material);
        }
        if (parsed.isEmpty()) {
            throw new IllegalArgumentException("Encryption key is not configured. Set the " + source + " environment variable using the format v1:<base64 key>.");
        }
        String active = activeVersion == null || activeVersion.isBlank()
                ? new ArrayList<>(parsed.keySet()).get(parsed.size() - 1)
                : activeVersion.trim();
        if (!parsed.containsKey(active)) {
            throw new IllegalArgumentException("Active key version " + active + " is not present in " + source + ". Available versions: " + parsed.keySet() + ".");
        }
        return new KeyRing(parsed, active, source);
    }

    /**
     * Creates a keyring from already decoded keys.
     *
     * @param keys Key material keyed by version, in the desired order
     * @param activeVersion The active version
     * @param source Name of the configuration source, used in error messages
     * @return The KeyRing
     */
    public static KeyRing of(Map<String, byte[]> keys, String activeVersion, String source) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("Keyring " + source + " does not contain any key.");
        }
        for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
            if (!KEY_VERSION.matcher(entry.getKey()).matches()) {
                throw new IllegalArgumentException("Invalid key version " + entry.getKey() + " in " + source + ".");
            }
            validateLength(entry.getValue().length, entry.getKey(), source);
        }
        if (!keys.containsKey(activeVersion)) {
            throw new IllegalArgumentException("Active key version " + activeVersion + " is not present in " + source + ".");
        }
        return new KeyRing(new LinkedHashMap<>(keys), activeVersion, source);
    }

    /**
     * Generates a random key suitable for a keyring entry.
     *
     * @return A Base64 encoded 32-byte key
     */
    public static String generateKey() {
        byte[] generated = new byte[KEY_LENGTH];
        RANDOM.nextBytes(generated);
        return Base64.getEncoder().encodeToString(generated);
    }

    /**
     * @return The version used for new encryptions/derivations
     */
    public String getActiveVersion() {
        return activeVersion;
    }

    /**
     * @return The key material of the active version
     */
    public byte[] getActive() {
        return get(activeVersion);
    }

    /**
     * Gets the key material of a specific version.
     *
     * @param version The key version
     * @return A copy of the key material, or null if the version is unknown
     */
    public byte[] get(String version) {
        byte[] material = keys.get(version);
        return material == null ? null : material.clone();
    }

    /**
     * @param version The key version
     * @return true if the version is present in this keyring
     */
    public boolean contains(String version) {
        return keys.containsKey(version);
    }

    /**
     * @return The configured key versions, ordered as configured
     */
    public List<String> getVersions() {
        return List.copyOf(keys.keySet());
    }

    /**
     * @return The configured keys, ordered as configured
     */
    public List<Entry> getEntries() {
        List<Entry> entries = new ArrayList<>();
        keys.forEach((version, material) -> entries.add(new Entry(version, material.clone())));
        return entries;
    }

    /**
     * @return Name of the configuration source this keyring was parsed from
     */
    public String getSource() {
        return source;
    }

    private static byte[] decodeMaterial(String material, String version, String source) {
        if (material.isEmpty()) {
            throw new IllegalArgumentException("Key " + version + " in " + source + " is empty.");
        }
        byte[] decoded = null;
        try {
            decoded = Base64.getDecoder().decode(material);
        } catch (IllegalArgumentException ex) {
            // not Base64, fall through to the raw representation
        }
        if (decoded != null && isValidKeyLength(decoded.length)) {
            return decoded;
        }
        byte[] raw = material.getBytes(StandardCharsets.UTF_8);
        if (isValidKeyLength(raw.length)) {
            return raw;
        }
        throw new IllegalArgumentException("Key " + version + " in " + source + " must be a Base64 encoded 16, 24 or 32 byte key (e.g. the output of 'openssl rand -base64 32').");
    }

    private static byte[] decodeLegacyMaterial(String material, String source) {
        byte[] raw = material.getBytes(StandardCharsets.UTF_8);
        if (isValidKeyLength(raw.length)) {
            return raw;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(material);
            if (isValidKeyLength(decoded.length)) {
                return decoded;
            }
        } catch (IllegalArgumentException ex) {
            // reported below
        }
        throw new IllegalArgumentException("Legacy key in " + source + " must be a 16, 24 or 32 byte string, or a Base64 encoded 16, 24 or 32 byte key.");
    }

    private static void validateLength(int length, String version, String source) {
        if (!isValidKeyLength(length)) {
            throw new IllegalArgumentException("Key " + version + " in " + source + " has invalid length " + length + ". Valid lengths are 16, 24 and 32 bytes.");
        }
    }

    private static boolean isValidKeyLength(int length) {
        for (int valid : VALID_KEY_LENGTHS) {
            if (valid == length) {
                return true;
            }
        }
        return false;
    }

    /**
     * A single entry of the keyring.
     */
    public record Entry(String version, byte[] key) {

        public Entry {
            key = key.clone();
        }

        @Override
        public byte[] key() {
            return key.clone();
        }
    }

}
