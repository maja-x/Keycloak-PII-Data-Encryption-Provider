/*
 * Crypto for Keycloak PII data encryption provider
 * Maja XBilling PII encryption implementation
 *
 * (c) 2026 Makara Mas
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * Deterministic, keyed hash (blind index) that allows PII protected with a
 * randomized encryption scheme to still be filtered with exact matches.
 *
 * <p>
 * Values are hashed with HMAC-SHA256 using a secret pepper. A plain hash would
 * be brute-forceable because PII such as email addresses and phone numbers has
 * low entropy, hence HMAC. The pepper is versioned ({@code v1:<hex>}) just like
 * the master keys, so a pepper can be rotated while hashes produced by the old
 * pepper are still recognised by {@link #candidates(String, PiiKind)} and
 * {@link #matches(String, String, PiiKind)}.</p>
 *
 * <p>
 * Values written by version 1.x of this provider were hashed with plain SHA-1
 * and are still recognised by {@link #isHash(String)} and matched by
 * {@link #matches(String, String, PiiKind)} until they are re-indexed.</p>
 *
 * @author Makara Mas (support@makaramas.com)
 */
public final class BlindIndex {

    private static final String ALGORITHM = "HmacSHA256";
    private static final Pattern VERSIONED_HASH = Pattern.compile("^v\\d+:[0-9a-fA-F]{64}$");
    private static final Pattern LEGACY_HASH = Pattern.compile("^[0-9a-fA-F]{40}$");

    private final KeyRing peppers;

    /**
     * @param peppers The pepper keyring
     */
    public BlindIndex(KeyRing peppers) {
        this.peppers = peppers;
    }

    /**
     * Computes the blind index of a value with the active pepper.
     *
     * @param value The plaintext value
     * @param kind The kind of value, used for canonicalization
     * @return The blind index ({@code <pepper version>:<hex>}), or null if the
     * value is null
     */
    public String search(String value, PiiKind kind) {
        if (value == null) {
            return null;
        }
        return peppers.getActiveVersion() + ":" + hash(peppers.getActive(), canonicalize(value, kind));
    }

    /**
     * Computes the blind index of a value with every configured pepper, plus
     * the legacy SHA-1 hash. Used to look up rows that have not been re-indexed
     * after a pepper rotation, mirroring a {@code WHERE hash = ANY(...)} query.
     *
     * @param value The plaintext value
     * @param kind The kind of value, used for canonicalization
     * @return The candidate hashes, the active one first
     */
    public List<String> searchAll(String value, PiiKind kind) {
        List<String> candidates = new ArrayList<>(candidates(value, kind));
        candidates.add(legacyHash(value));
        return candidates;
    }

    /**
     * Computes the blind index of a value with every configured pepper.
     *
     * @param value The plaintext value
     * @param kind The kind of value, used for canonicalization
     * @return The candidate hashes, the active one first
     */
    public List<String> candidates(String value, PiiKind kind) {
        if (value == null) {
            return List.of();
        }
        String canonical = canonicalize(value, kind);
        List<String> candidates = new ArrayList<>();
        candidates.add(search(value, kind));
        for (KeyRing.Entry pepper : peppers.getEntries()) {
            if (!pepper.version().equals(peppers.getActiveVersion())) {
                candidates.add(pepper.version() + ":" + hash(pepper.key(), canonical));
            }
        }
        return candidates;
    }

    /**
     * Checks whether a stored blind index matches a plaintext value. Both
     * versioned HMAC hashes and legacy SHA-1 hashes are supported, so rows that
     * have not been re-indexed yet can still be found.
     *
     * @param storedHash The hash read from the database
     * @param value The plaintext value
     * @param kind The kind of value, used for canonicalization
     * @return true if the stored hash belongs to the passed value
     */
    public boolean matches(String storedHash, String value, PiiKind kind) {
        if (storedHash == null || value == null) {
            return false;
        }
        if (LEGACY_HASH.matcher(storedHash).matches()) {
            return storedHash.equalsIgnoreCase(legacyHash(value));
        }
        int separator = storedHash.indexOf(':');
        if (separator < 0) {
            return false;
        }
        String version = storedHash.substring(0, separator);
        byte[] pepper = peppers.get(version);
        if (pepper == null) {
            return false;
        }
        return storedHash.substring(separator + 1)
                .equalsIgnoreCase(hash(pepper, canonicalize(value, kind)));
    }

    /**
     * Checks whether a stored blind index was produced with the active pepper.
     *
     * @param storedHash The hash read from the database
     * @return true if the hash needs to be recomputed
     */
    public boolean needsReindex(String storedHash) {
        if (storedHash == null) {
            return false;
        }
        return !storedHash.startsWith(peppers.getActiveVersion() + ":");
    }

    /**
     * Checks whether a value is a blind index, either the versioned HMAC-SHA256
     * format of this version or the plain SHA-1 format of version 1.x.
     *
     * @param value The value to check
     * @return true if the value is a blind index
     */
    public static boolean isHash(String value) {
        return value != null && (VERSIONED_HASH.matcher(value).matches() || LEGACY_HASH.matcher(value).matches());
    }

    /**
     * Computes the plain SHA-1 hash used by version 1.x of this provider.
     *
     * @param value The value to hash
     * @return The lowered-hex SHA-1 hash, or null if the value is null
     */
    public static String legacyHash(String value) {
        return value == null ? null : DigestUtils.sha1Hex(PiiKind.GENERIC.canonicalize(value));
    }

    private static String canonicalize(String value, PiiKind kind) {
        return (kind == null ? PiiKind.GENERIC : kind).canonicalize(value);
    }

    private static String hash(byte[] pepper, String canonical) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(pepper, ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to compute blind index using " + ALGORITHM, ex);
        }
    }

}
