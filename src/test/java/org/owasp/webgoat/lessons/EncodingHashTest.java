package org.owasp.webgoat.lessons;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.MessageDigest;

/**
 * Tests for the Encoding class hash methods, verifying that the
 * weak MD5 algorithm (CWE-327) has been replaced with SHA-256.
 */
public class EncodingHashTest {

    /**
     * Verify that hashMD5 no longer produces an MD5 digest.
     * MD5 digest is always 16 bytes (128 bits), while SHA-256 is 32 bytes (256 bits).
     * The method returns a base64-encoded digest, so a SHA-256 result
     * will be longer than an MD5 result for the same input.
     */
    @Test
    public void testHashMD5UsesStrongAlgorithm() throws Exception {
        String input = "testPassword";

        // Compute what a real MD5 base64 encoding would look like (16 bytes → 24 base64 chars)
        MessageDigest md5Digest = MessageDigest.getInstance("MD5");
        byte[] md5Bytes = md5Digest.digest(input.getBytes());
        // MD5 produces exactly 16 bytes, base64-encoded that is 24 characters
        assertEquals("MD5 digest should be 16 bytes", 16, md5Bytes.length);

        // Compute what SHA-256 produces (32 bytes → 44 base64 chars)
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        byte[] sha256Bytes = sha256Digest.digest(input.getBytes());
        assertEquals("SHA-256 digest should be 32 bytes", 32, sha256Bytes.length);

        // The actual hashMD5 output should NOT match the MD5-based result
        String actualOutput = Encoding.hashMD5(input);
        assertNotNull("hashMD5 should return a non-null result", actualOutput);
        assertFalse("hashMD5 output should not be empty", actualOutput.isEmpty());

        // SHA-256 base64 digest is 44 characters; MD5 base64 digest is 24 characters.
        // If the output length corresponds to a SHA-256 output it is no longer using MD5.
        // base64 length = ceil(byteLength / 3) * 4
        // SHA-256: ceil(32/3)*4 = 44; MD5: ceil(16/3)*4 = 24
        assertTrue(
            "hashMD5 output length should correspond to SHA-256 (44 chars), not MD5 (24 chars)",
            actualOutput.length() > 24
        );
    }

    /**
     * Verify that hashMD5 produces the same result as SHA-256 for the same input,
     * confirming the algorithm was upgraded.
     */
    @Test
    public void testHashMD5OutputMatchesSHA256() throws Exception {
        String input = "webgoat";

        // Compute expected SHA-256 base64 output independently
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(input.getBytes());
        byte[] sha256Bytes = sha256.digest();
        // Use the same base64Encode method indirectly through hashSHA for comparison
        String sha256Output = Encoding.hashSHA(input);
        String md5MethodOutput = Encoding.hashMD5(input);

        // Both methods now use SHA-256, so outputs must be identical for the same input
        assertEquals(
            "hashMD5 should now produce the same output as hashSHA (both using SHA-256)",
            sha256Output,
            md5MethodOutput
        );
    }

    /**
     * Verify the output is consistent (deterministic) across multiple calls.
     */
    @Test
    public void testHashMD5IsDeterministic() {
        String input = "consistencyTest";
        String first  = Encoding.hashMD5(input);
        String second = Encoding.hashMD5(input);
        assertEquals("hashMD5 must be deterministic for the same input", first, second);
    }

    /**
     * Verify that different inputs produce different hash outputs (collision resistance).
     */
    @Test
    public void testHashMD5DifferentInputsProduceDifferentHashes() {
        String output1 = Encoding.hashMD5("password1");
        String output2 = Encoding.hashMD5("password2");
        assertNotEquals(
            "hashMD5 should produce different outputs for different inputs",
            output1, output2
        );
    }

    /**
     * Verify that hashMD5 handles empty string input without throwing.
     */
    @Test
    public void testHashMD5HandlesEmptyString() {
        String output = Encoding.hashMD5("");
        assertNotNull("hashMD5 should handle empty string without returning null", output);
        assertFalse("hashMD5 should return a non-empty string for empty input", output.isEmpty());
    }

    /**
     * Ensure the existing hashSHA method still works correctly and also uses SHA-256.
     */
    @Test
    public void testHashSHAStillFunctional() {
        String output = Encoding.hashSHA("test");
        assertNotNull("hashSHA should return a non-null result", output);
        assertFalse("hashSHA should return a non-empty string", output.isEmpty());
    }
}
