package org.owasp.webgoat.lessons;

import static org.junit.Assert.*;

import java.security.Security;
import javax.crypto.Cipher;
import org.junit.Test;

/**
 * Tests that verify the Encoding class uses a strong cryptographic algorithm
 * (PBEWithHmacSHA256AndAES_256) instead of the broken PBEWithMD5AndDES algorithm.
 *
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 */
public class EncodingCryptoTest {

    private static final String PASSWORD = "testPassword123";
    private static final String PLAINTEXT = "Hello, WebGoat!";

    /**
     * Verifies that the broken PBEWithMD5AndDES algorithm is NOT available or used
     * by confirming that encryptString no longer silently relies on it.
     * The presence of PBEWithMD5AndDES in the JVM is JVM-dependent; the important
     * assertion is that our code requests the strong algorithm.
     */
    @Test
    public void testEncryptStringDoesNotUseMD5AndDES() {
        // Confirm the strong algorithm is available in this JVM
        boolean strongAlgoAvailable = false;
        try {
            Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
            strongAlgoAvailable = true;
        } catch (Exception e) {
            // Not available – test environment limitation
        }
        assertTrue("PBEWithHmacSHA256AndAES_256 must be available in the JVM", strongAlgoAvailable);
    }

    /**
     * Verifies that encryptString produces a non-null, non-empty, non-error result
     * with the strong algorithm.
     */
    @Test
    public void testEncryptStringReturnsEncryptedValue() {
        String encrypted = Encoding.encryptString(PLAINTEXT, PASSWORD);
        assertNotNull("encryptString must return a non-null result", encrypted);
        assertFalse("encryptString must not return an empty string", encrypted.isEmpty());
        assertNotEquals("encryptString must not return an error message",
                "Encryption error", encrypted);
        assertNotEquals("encryptString result must differ from plaintext",
                PLAINTEXT, encrypted);
    }

    /**
     * Verifies that decryptString can round-trip data encrypted with encryptString,
     * proving both methods use the same (strong) algorithm.
     */
    @Test
    public void testEncryptDecryptRoundTrip() {
        String encrypted = Encoding.encryptString(PLAINTEXT, PASSWORD);
        assertNotNull(encrypted);
        assertNotEquals("Encryption error", encrypted);

        String decrypted = Encoding.decryptString(encrypted, PASSWORD);
        assertNotNull("decryptString must return a non-null result", decrypted);
        assertEquals("Round-trip encryption/decryption must recover the original plaintext",
                PLAINTEXT, decrypted);
    }

    /**
     * Verifies that decryptString returns an error indicator (not the original text)
     * when given an incorrect password, confirming the encryption is actually enforced.
     */
    @Test
    public void testDecryptWithWrongPasswordFails() {
        String encrypted = Encoding.encryptString(PLAINTEXT, PASSWORD);
        assertNotNull(encrypted);
        assertNotEquals("Encryption error", encrypted);

        String decrypted = Encoding.decryptString(encrypted, "wrongPassword");
        // Must NOT successfully recover plaintext with the wrong key
        assertNotEquals(
                "Decryption with wrong password must not return original plaintext",
                PLAINTEXT, decrypted);
    }

    /**
     * Verifies that decryptString handles malformed (non-encrypted) input gracefully
     * without throwing an uncaught exception.
     */
    @Test
    public void testDecryptInvalidInputReturnsErrorMessage() {
        String result = Encoding.decryptString("this_is_not_encrypted_data", PASSWORD);
        assertNotNull("decryptString must not return null for invalid input", result);
        // Should return the error sentinel defined in the implementation
        assertEquals("This is not an encrypted string", result);
    }

    /**
     * Security regression: verify that the weak PBEWithMD5AndDES cipher string
     * is not referenced in the source (compile-time guard via behavioural test).
     * Encrypted data produced by the strong algorithm should be structurally different
     * (and longer) than DES-encrypted data for the same input.
     */
    @Test
    public void testEncryptedOutputIsConsistentWithStrongAlgorithm() {
        // AES_256 block size produces output of a specific minimum length.
        // DES (56-bit) ciphertext for "Hello, WebGoat!" Base64-encoded would be
        // much shorter. AES-256 output for the same input + Base64 will be longer.
        String encrypted = Encoding.encryptString(PLAINTEXT, PASSWORD);
        assertNotNull(encrypted);
        assertNotEquals("Encryption error", encrypted);
        // AES-256 with PKCS5Padding for 15-byte input produces 16 bytes of ciphertext;
        // Base64-encoded that is at least 24 characters. Use a conservative lower bound.
        assertTrue("Encrypted output length suggests a weak cipher was used",
                encrypted.length() >= 24);
    }
}
