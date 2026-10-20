/*
 * PII Chiper tests.
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SystemStubsExtension.class)
class PiiCipherTest {

    @SystemStub
    private EnvironmentVariables environmentVariables;

    private static final String LEGACY_KEY = "1234567891123456";
    private static final String LEGACY_CIPHERTEXT = "$$$GTaogsGC8vbgE098AN9kC+UCHD8vYzVgFF0hFDnuKIw=";
    private static final String AAD = PiiCipher.fieldContext("user", "1f7a3d2c-0000-0000-0000-000000000001", "email");

    private String key1;
    private String key2;

    @BeforeEach
    void setUp() {
        PiiCipher.reset();
        key1 = KeyRing.generateKey();
        key2 = KeyRing.generateKey();
        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1);
    }

    @Test
    void testEncryptDecryptRoundTripWithAad() {
        PiiCipher cipher = PiiCipher.fromEnv();

        String protectedValue = cipher.encryptString("budi@example.com", AAD);

        assertTrue(protectedValue.startsWith(ProtectedValue.CIPHERTEXT_PREFIX + ProtectedValue.ENVELOPE_VERSION + ":v1:"));
        assertEquals("budi@example.com", cipher.decryptString(protectedValue, AAD));
        assertEquals("budi@example.com", cipher.decrypt(ProtectedValue.parse(protectedValue), AAD));
        assertNotNull(ProtectedValue.parse(protectedValue));
        assertEquals("v1", ProtectedValue.parse(protectedValue).getKeyVersion());
        assertFalse(cipher.needsRotation(protectedValue));
        assertNull(cipher.encryptString(null, AAD));
        assertNull(cipher.decryptString(null, AAD));
    }

    @Test
    void testEncryptionUsesAFreshDataKeyPerValue() {
        PiiCipher cipher = PiiCipher.fromEnv();

        String first = cipher.encryptString("budi@example.com", AAD);
        String second = cipher.encryptString("budi@example.com", AAD);

        assertNotEquals(first, second);
        assertEquals("budi@example.com", cipher.decryptString(first, AAD));
        assertEquals("budi@example.com", cipher.decryptString(second, AAD));
        assertNotEquals(ProtectedValue.parse(first).getDataKey(), ProtectedValue.parse(second).getDataKey());
    }

    @Test
    void testCiphertextCannotBeMovedToAnotherFieldOrRow() {
        PiiCipher cipher = PiiCipher.fromEnv();
        String protectedValue = cipher.encryptString("budi@example.com", AAD);

        String otherFieldAad = PiiCipher.fieldContext("user", "1f7a3d2c-0000-0000-0000-000000000001", "username");
        String otherUserAad = PiiCipher.fieldContext("user", "1f7a3d2c-0000-0000-0000-000000000002", "email");

        assertNotEquals("budi@example.com", cipher.decryptString(protectedValue, otherFieldAad));
        assertNotEquals("budi@example.com", cipher.decryptString(protectedValue, otherUserAad));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(ProtectedValue.parse(protectedValue), otherUserAad));
    }

    @Test
    void testValuesAreStillReadableAfterTheMasterKeyIsRotated() {
        PiiCipher cipher = PiiCipher.fromEnv();
        String oldValue = cipher.encryptString("budi@example.com", AAD);

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1 + ",v2:" + key2);
        PiiCipher.reset();
        PiiCipher rotated = PiiCipher.fromEnv();

        assertTrue(rotated.encryptString("new@example.com", AAD).startsWith("$$$" + ProtectedValue.ENVELOPE_VERSION + ":v2:"));
        assertEquals("budi@example.com", rotated.decryptString(oldValue, AAD));
        assertTrue(rotated.needsRotation(ProtectedValue.parse(oldValue)));

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v2:" + key2);
        PiiCipher.reset();
        PiiCipher onlyNewKey = PiiCipher.fromEnv();

        assertEquals(oldValue, onlyNewKey.decryptString(oldValue, AAD), "old key is no longer configured so the value cannot be read");
        assertEquals("new@example.com", onlyNewKey.decryptString(rotated.encryptString("new@example.com", AAD), AAD));
    }

    @Test
    void testRewrapDataKeyKeepsTheCiphertextAndChangesOnlyTheKeyVersion() {
        PiiCipher cipher = PiiCipher.fromEnv();
        ProtectedValue value = cipher.encrypt("budi@example.com", AAD);

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1 + ",v2:" + key2);
        PiiCipher.reset();
        PiiCipher rotated = PiiCipher.fromEnv();

        assertTrue(rotated.needsRotation(value));
        ProtectedValue rewrapped = rotated.rewrapDataKey(value);

        assertEquals("v2", rewrapped.getKeyVersion());
        assertEquals(value.getCiphertext(), rewrapped.getCiphertext());
        assertEquals("budi@example.com", rotated.decrypt(rewrapped, AAD));
        assertFalse(rotated.needsRotation(rewrapped));

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v2:" + key2);
        PiiCipher.reset();
        assertEquals("budi@example.com", PiiCipher.fromEnv().decrypt(rewrapped, AAD));
    }

    @Test
    void testRotateDataKeyReencryptsTheValueAndKeepsTheBlindIndex() {
        PiiCipher cipher = PiiCipher.fromEnv();
        ProtectedValue value = cipher.protect("Budi@Example.com ", PiiKind.EMAIL, AAD);

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1 + ",v2:" + key2);
        PiiCipher.reset();
        PiiCipher rotated = PiiCipher.fromEnv();
        ProtectedValue reencrypted = rotated.rotateDataKey(value, AAD);

        assertNotEquals(value.getCiphertext(), reencrypted.getCiphertext());
        assertEquals("v2", reencrypted.getKeyVersion());
        assertEquals(value.getIndex(), reencrypted.getIndex());
        assertEquals("Budi@Example.com ", rotated.decrypt(reencrypted, AAD));
        assertTrue(rotated.matchesHash(reencrypted.getIndex(), "budi@example.com", PiiKind.EMAIL));
    }

    @Test
    void testCiphertextFromVersion1StillDecrypts() {
        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, LEGACY_KEY);
        PiiCipher.reset();

        assertEquals("test", PiiCipher.fromEnv().decryptString(LEGACY_CIPHERTEXT, AAD));
    }

    @Test
    void testLegacyCiphertextSurvivesTheUpgradeToVersionedKeys() {
        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1 + "," + LEGACY_KEY);
        PiiCipher.reset();

        assertEquals("test", PiiCipher.fromEnv().decryptString(LEGACY_CIPHERTEXT, AAD));
    }

    @Test
    void testCiphertextOfAMaximumLengthUsernameFitsTheColumn() {
        PiiCipher cipher = PiiCipher.fromEnv();
        String username = "u".repeat(255);

        String protectedValue = cipher.encryptString(username, AAD);

        // USER_ENTITY_ENCRYPTED.USERNAME is VARCHAR(500)
        assertTrue(protectedValue.length() <= 500, "serialized value is " + protectedValue.length() + " characters long");
        assertEquals(username, cipher.decryptString(protectedValue, AAD));
    }

    @Test
    void testTamperedCiphertextIsNotDecrypted() {
        PiiCipher cipher = PiiCipher.fromEnv();
        String protectedValue = cipher.encryptString("budi@example.com", AAD);
        String tampered = protectedValue.substring(0, protectedValue.length() - 4) + "AAAA";

        assertEquals(tampered, cipher.decryptString(tampered, AAD));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(ProtectedValue.parse(tampered), AAD));
    }

    @Test
    void testPlaintextValuesAreReturnedAsIs() {
        PiiCipher cipher = PiiCipher.fromEnv();

        assertEquals("plain", cipher.decryptString("plain", AAD));
        assertFalse(PiiCipher.isProtected("plain"));
        assertTrue(PiiCipher.isProtected(LEGACY_CIPHERTEXT));
    }

    @Test
    void testInvalidKeyConfigurationIsRejected() {
        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "invalid");
        PiiCipher.reset();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, PiiCipher::fromEnv);
        assertTrue(thrown.getMessage().contains("16, 24 or 32 byte"));
    }

    @Test
    void testInstanceIsCachedUntilReset() {
        PiiCipher first = PiiCipher.getInstance();
        PiiCipher second = PiiCipher.getInstance();
        assertSame(first, second);

        environmentVariables.set(PiiCipher.ENV_MASTER_KEYS, "v1:" + key1 + ",v2:" + key2);
        PiiCipher.reset();

        assertEquals("v2", PiiCipher.getInstance().getActiveKeyVersion());
    }

}
