/*
 * PII Data Encryption for Keycloak
 * Copyright (c) 2026 Makara Mas
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.util.Locale;

/**
 * Kind of PII value. The kind determines how a value is canonicalized before it
 * is fed into the blind index, so that equivalent representations of the same
 * value produce the same hash and remain searchable.
 *
 * @author Makara Mas <support@makaramas.com>
 */
public enum PiiKind {

    /**
     * Email address: trimmed and lowercased.
     */
    EMAIL,
    /**
     * Phone number: formatting characters are removed and the number is
     * normalized into its E.164 representation using the configured country
     * code (see {@link #ENV_COUNTRY_CODE}).
     */
    PHONE,
    /**
     * Any other value: trimmed and lowercased. Lowercasing is intentional to
     * preserve the case-insensitive lookups Keycloak performs on usernames,
     * names and attributes.
     */
    GENERIC;

    /**
     * Environment variable that holds the country calling code used to
     * normalize phone numbers without an international prefix.
     */
    public static final String ENV_COUNTRY_CODE = "KC_PII_COUNTRY_CODE";

    private static final String DEFAULT_COUNTRY_CODE = "62";

    /**
     * Canonicalizes a value of this kind.
     *
     * @param value The raw value
     * @return The canonical representation, or null if the input is null
     */
    public String canonicalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return switch (this) {
            case EMAIL, GENERIC ->
                trimmed.toLowerCase(Locale.ROOT);
            case PHONE ->
                canonicalizePhone(trimmed);
        };
    }

    /**
     * Normalizes a phone number into its E.164 representation. Formatting
     * characters are removed, {@code 00} prefixes are converted to {@code +}
     * and a leading {@code 0} is replaced with the configured country code.
     *
     * @param value The raw phone number
     * @return The normalized phone number
     */
    static String canonicalizePhone(String value) {
        String digits = value.replaceAll("[^0-9+]", "");
        if (digits.startsWith("00")) {
            digits = "+" + digits.substring(2);
        }
        if (digits.startsWith("+")) {
            return "+" + digits.substring(1).replace("+", "");
        }
        digits = digits.replace("+", "");
        String countryCode = countryCode();
        if (digits.startsWith("0")) {
            return "+" + countryCode + digits.substring(1);
        }
        if (!countryCode.isEmpty() && digits.startsWith(countryCode)) {
            return "+" + digits;
        }
        return digits;
    }

    private static String countryCode() {
        String configured = System.getenv(ENV_COUNTRY_CODE);
        if (configured == null || configured.isBlank()) {
            return DEFAULT_COUNTRY_CODE;
        }
        return configured.replaceAll("[^0-9]", "");
    }

}
