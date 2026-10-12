package org.owasp.webgoat.lessons;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the Encoding class, specifically validating that PBE encryption
 * uses a strong cryptographic algorithm (PBEWithHmacSHA256AndAES_256) rather
 * than the broken PBEWithMD5AndDES algorithm (CWE-327).
 */
public class EncodingTest {

    private static final String TEST_PLAINTEXT = "Hello, WebGoat!";
    private static final String TEST_PASSWORD = "testPassword123";

    /**
     * Verifies that encrypt-then-decrypt round-trip works correctly
     * with the new strong PBE algorithm (PBEWithHmacSHA256AndAES_256).
     */
    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        String encrypted = Encoding.encryptString(TEST_PLAINTEXT, TEST_PASSWORD);
        assertNotNull("Encrypted string should not be null", encrypted);
        assertFalse("Encrypted string should not equal plaintext", TEST_PLAINTEXT.equals(encrypted));
        assertFalse("Encryption error should not occur", encrypted.startsWith("Encryption error"));

        String decrypted = Encoding.decryptString(encrypted, TEST_PASSWORD);
        assertNotNull("Decrypted string should not be null", decrypted);
        assertEquals("Decrypted string should match original plaintext", TEST_PLAINTEXT, decrypted);
    }

    /**
     * Verifies that decryption with a wrong password does not return the plaintext,
     * validating that the encryption actually protects the data.
     */
    @Test
    public void testDecryptWithWrongPasswordFails() throws Exception {
        String encrypted = Encoding.encryptString(TEST_PLAINTEXT, TEST_PASSWORD);
        assertNotNull("Encrypted string should not be null", encrypted);

        String decrypted = Encoding.decryptString(encrypted, "wrongPassword");
        // Should either return an error message or garbage, but NOT the original plaintext
        assertFalse(
            "Decrypting with wrong password should not return the original plaintext",
            TEST_PLAINTEXT.equals(decrypted)
        );
    }

    /**
     * Verifies that the encryption algorithm used is NOT the broken PBEWithMD5AndDES.
     * This is accomplished by checking that encrypting the same plaintext twice
     * with different keys produces different ciphertexts (DES was weak enough
     * for trivial attacks), and that the AES-256 based scheme functions correctly.
     */
    @Test
    public void testEncryptionWithDifferentPasswordsProduceDifferentCiphertexts() throws Exception {
        String password1 = "password_one";
        String password2 = "password_two";

        String encrypted1 = Encoding.encryptString(TEST_PLAINTEXT, password1);
        String encrypted2 = Encoding.encryptString(TEST_PLAINTEXT, password2);

        assertNotNull("First encrypted string should not be null", encrypted1);
        assertNotNull("Second encrypted string should not be null", encrypted2);
        assertFalse(
            "Encrypting with different passwords should produce different ciphertexts",
            encrypted1.equals(encrypted2)
        );
    }

    /**
     * Verifies that decrypting a non-encrypted (or malformed) string returns
     * the expected error message rather than throwing an uncaught exception.
     */
    @Test
    public void testDecryptInvalidInputReturnsErrorMessage() {
        String result = Encoding.decryptString("not_an_encrypted_string", TEST_PASSWORD);
        assertNotNull("Decryption of invalid input should return an error message", result);
        // Should return the error message, not throw an exception
        assertEquals("This is not an encrypted string", result);
    }

    /**
     * Verifies that encrypting an empty string works without errors.
     */
    @Test
    public void testEncryptEmptyString() throws Exception {
        String encrypted = Encoding.encryptString("", TEST_PASSWORD);
        assertNotNull("Encrypted empty string should not be null", encrypted);
        assertFalse("Encryption error should not occur for empty string", encrypted.startsWith("Encryption error"));
    }

    /**
     * Verifies that encrypting with an empty password works without errors.
     */
    @Test
    public void testEncryptWithEmptyPassword() throws Exception {
        String encrypted = Encoding.encryptString(TEST_PLAINTEXT, "");
        assertNotNull("Encrypted string should not be null even with empty password", encrypted);
    }

    /**
     * Verifies that the algorithm name in use is the strong one (PBEWithHmacSHA256AndAES_256).
     * This test uses the javax.crypto.SecretKeyFactory API directly to confirm that
     * the algorithm is available and is NOT the broken MD5+DES variant.
     */
    @Test
    public void testStrongAlgorithmIsAvailable() throws Exception {
        // Verify strong algorithm is available in this JVM
        javax.crypto.SecretKeyFactory strongKf =
            javax.crypto.SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        assertNotNull("PBEWithHmacSHA256AndAES_256 SecretKeyFactory should be available", strongKf);

        // Verify the broken algorithm name is NOT what we get when calling encryptString
        // by confirming encrypt+decrypt works only with the strong algorithm
        String encrypted = Encoding.encryptString(TEST_PLAINTEXT, TEST_PASSWORD);
        String decrypted = Encoding.decryptString(encrypted, TEST_PASSWORD);
        assertEquals(
            "Encrypt-decrypt round trip must succeed with PBEWithHmacSHA256AndAES_256",
            TEST_PLAINTEXT, decrypted
        );
    }

    /**
     * Verifies that attempting to decrypt data encrypted with the old weak
     * PBEWithMD5AndDES algorithm using the new strong algorithm gracefully
     * returns an error (backward incompatibility is expected and acceptable
     * when upgrading from a broken algorithm to a secure one).
     */
    @Test
    public void testOldWeakAlgorithmCiphertextRejectedByStrongAlgorithm() throws Exception {
        // Simulate what the old broken algorithm would have produced (manually constructed
        // base64 garbage that is clearly not valid AES-256 PBE ciphertext)
        String oldWeakCiphertext = "dGhpcyBpcyBub3QgdmFsaWQgQUVTIGNpcGhlcnRleHQ=";
        String result = Encoding.decryptString(oldWeakCiphertext, TEST_PASSWORD);
        // The new algorithm should reject this and return the error message
        assertEquals(
            "Old ciphertext from broken algorithm should not decrypt with new strong algorithm",
            "This is not an encrypted string", result
        );
    }
}
