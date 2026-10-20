/**
 * KeyRing tests.
 */
package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyRingTest {

    private static final String SOURCE = "TEST_KEYS";

    private final String key1 = KeyRing.generateKey();
    private final String key2 = KeyRing.generateKey();

    @Test
    void testActiveVersionDefaultsToLastEntry() {
        KeyRing ring = KeyRing.parse("v1:" + key1 + ",v2:" + key2, null, SOURCE);

        assertEquals("v2", ring.getActiveVersion());
        assertEquals(List.of("v1", "v2"), ring.getVersions());
        assertArrayEquals(Base64.getDecoder().decode(key1), ring.get("v1"));
        assertArrayEquals(Base64.getDecoder().decode(key2), ring.getActive());
        assertTrue(ring.contains("v1"));
        assertFalse(ring.contains("v3"));
        assertNull(ring.get("v3"));
    }

    @Test
    void testExplicitActiveVersion() {
        KeyRing ring = KeyRing.parse("v1:" + key1 + ",v2:" + key2, "v1", SOURCE);

        assertEquals("v1", ring.getActiveVersion());
        assertArrayEquals(Base64.getDecoder().decode(key1), ring.getActive());
    }

    @Test
    void testUnknownActiveVersionIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> KeyRing.parse("v1:" + key1, "v9", SOURCE));

        assertTrue(thrown.getMessage().contains("v9"));
        assertTrue(thrown.getMessage().contains("Available versions"));
    }

    @Test
    void testDuplicateVersionIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> KeyRing.parse("v1:" + key1 + ",v1:" + key2, null, SOURCE));

        assertTrue(thrown.getMessage().contains("Duplicate key version v1"));
    }

    @Test
    void testLegacyKeyWithoutVersionUsesRawBytes() {
        KeyRing ring = KeyRing.parse("1234567891123456", null, SOURCE);

        assertEquals(KeyRing.LEGACY_VERSION, ring.getActiveVersion());
        assertArrayEquals("1234567891123456".getBytes(StandardCharsets.UTF_8), ring.getActive());
    }

    @Test
    void testOnlyOneLegacyKeyIsAllowed() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> KeyRing.parse("1234567891123456,1234567891123457", null, SOURCE));

        assertTrue(thrown.getMessage().contains("Only one key without version prefix"));
    }

    @Test
    void testInvalidKeyLengthIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> KeyRing.parse("v1:invalid", null, SOURCE));

        assertTrue(thrown.getMessage().contains("16, 24 or 32 byte"));
    }

    @Test
    void testMissingConfigurationIsRejected() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> KeyRing.parse(" ", null, SOURCE));

        assertTrue(thrown.getMessage().contains("not configured"));
    }

    @Test
    void testGeneratedKeyIsA32ByteBase64String() {
        String generated = KeyRing.generateKey();

        assertEquals(KeyRing.KEY_LENGTH, Base64.getDecoder().decode(generated).length);
    }

    @Test
    void testOfValidatesActiveVersionAndVersions() {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        keys.put("v1", Base64.getDecoder().decode(key1));
        keys.put("v2", Base64.getDecoder().decode(key2));

        KeyRing ring = KeyRing.of(keys, "v2", SOURCE);
        assertEquals("v2", ring.getActiveVersion());

        assertThrows(IllegalArgumentException.class, () -> KeyRing.of(keys, "v3", SOURCE));
        assertThrows(IllegalArgumentException.class, () -> KeyRing.of(Map.of("1", new byte[16]), "1", SOURCE));
    }

}
