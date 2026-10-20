/*
 * Blind index tests. These tests are not exhaustive, but they cover the most important aspects of the blind index functionality.
 * Author: Makara Mas <support@makaramas.com>
 */

package my.unifi.eset.keycloak.piidataencryption.crypto;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BlindIndexTest {

    private final byte[] pepper1 = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private final byte[] pepper2 = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8);

    private BlindIndex blindIndex(String... versions) {
        Map<String, byte[]> peppers = new LinkedHashMap<>();
        for (String version : versions) {
            peppers.put(version, "v1".equals(version) ? pepper1 : pepper2);
        }
        return new BlindIndex(KeyRing.of(peppers, versions[versions.length - 1], "TEST_PEPPERS"));
    }

    @Test
    void testSearchIsDeterministicAndVersioned() {
        BlindIndex index = blindIndex("v1");

        String hash = index.search("budi@example.com", PiiKind.EMAIL);

        assertTrue(hash.matches("^v1:[0-9a-f]{64}$"));
        assertEquals(hash, index.search("budi@example.com", PiiKind.EMAIL));
        assertNotEquals(hash, index.search("other@example.com", PiiKind.EMAIL));
        assertNotEquals(hash, blindIndex("v2").search("budi@example.com", PiiKind.EMAIL));
    }

    @Test
    void testEmailCanonicalizationMakesLookupsCaseInsensitive() {
        BlindIndex index = blindIndex("v1");

        assertEquals(
                index.search("budi@example.com", PiiKind.EMAIL),
                index.search("  Budi@Example.COM  ", PiiKind.EMAIL));
    }

    @Test
    void testPhoneCanonicalizationNormalizesToE164() {
        BlindIndex index = blindIndex("v1");

        assertEquals(
                index.search("+62 812-3456-7890", PiiKind.PHONE),
                index.search("081234567890", PiiKind.PHONE));
        assertNotEquals(
                index.search("081234567890", PiiKind.PHONE),
                index.search("081234567891", PiiKind.PHONE));
    }

    @Test
    void testSearchAllIncludesPreviousPeppersAndTheLegacyHash() {
        BlindIndex index = blindIndex("v1", "v2");
        String legacy = BlindIndex.legacyHash("budi@example.com");

        List<String> candidates = index.searchAll("budi@example.com", PiiKind.EMAIL);

        assertTrue(candidates.get(0).startsWith("v2:"), "active pepper first");
        assertTrue(candidates.contains(index.search("budi@example.com", PiiKind.EMAIL)));
        assertEquals(3, candidates.size());
        assertEquals(legacy, candidates.get(2));
    }

    @Test
    void testMatchesSupportsPreviousPeppersAndLegacyHashes() {
        BlindIndex oldIndex = blindIndex("v1");
        BlindIndex newIndex = blindIndex("v1", "v2");

        String oldPepperHash = oldIndex.search("budi@example.com", PiiKind.EMAIL);
        String legacyHash = BlindIndex.legacyHash("budi@example.com");

        assertTrue(newIndex.matches(oldPepperHash, "  BUDI@example.com", PiiKind.EMAIL));
        assertTrue(newIndex.matches(legacyHash, "budi@example.com", PiiKind.EMAIL));
        assertTrue(newIndex.matches(legacyHash.toUpperCase(), "budi@example.com", PiiKind.EMAIL));
        assertFalse(newIndex.matches(oldPepperHash, "other@example.com", PiiKind.EMAIL));
        assertFalse(newIndex.matches(null, "budi@example.com", PiiKind.EMAIL));
        assertFalse(newIndex.matches("not-a-hash", "budi@example.com", PiiKind.EMAIL));
    }

    @Test
    void testMatchesRejectsHashesProducedByAKeyThatIsNoLongerConfigured() {
        BlindIndex rotated = blindIndex("v2");
        String hashFromV1 = blindIndex("v1").search("budi@example.com", PiiKind.EMAIL);

        assertFalse(rotated.matches(hashFromV1, "budi@example.com", PiiKind.EMAIL));
    }

    @Test
    void testNeedsReindex() {
        BlindIndex index = blindIndex("v1", "v2");

        assertFalse(index.needsReindex(index.search("budi@example.com", PiiKind.EMAIL)));
        assertTrue(index.needsReindex(blindIndex("v1").search("budi@example.com", PiiKind.EMAIL)));
        assertTrue(index.needsReindex(BlindIndex.legacyHash("budi@example.com")));
        assertFalse(index.needsReindex(null));
    }

    @Test
    void testIsHashRecognizesCurrentAndLegacyFormat() {
        BlindIndex index = blindIndex("v1");

        assertTrue(BlindIndex.isHash(index.search("budi@example.com", PiiKind.EMAIL)));
        assertTrue(BlindIndex.isHash(BlindIndex.legacyHash("budi@example.com")));
        assertFalse(BlindIndex.isHash("budi@example.com"));
        assertFalse(BlindIndex.isHash("v1:not-hex"));
        assertFalse(BlindIndex.isHash(null));
    }

    @Test
    void testLegacyHashMatchesTheFormatOfVersion1() {
        assertEquals("45c571a156ddcef41351a713bcddee5ba7e95460", BlindIndex.legacyHash("TestUser"));
    }

}
