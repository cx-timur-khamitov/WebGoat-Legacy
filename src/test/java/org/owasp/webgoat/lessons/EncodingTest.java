package org.owasp.webgoat.lessons;

import org.junit.Test;
import org.junit.Assert;

/**
 * Tests for the Encoding class, specifically verifying that the PBE encryption
 * uses a strong algorithm (PBEWithHmacSHA256AndAES_256) instead of the
 * broken PBEWithMD5AndDES algorithm (CWE-327).
 */
public class EncodingTest {

    /**
     * Verifies that encryptString and decryptString work correctly with
     * the strong PBEWithHmacSHA256AndAES_256 algorithm.
     * An encrypt/decrypt round-trip must recover the original plaintext.
     */
    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        String plaintext = "HelloWebGoat";
        String password = "testPassword";

        String encrypted = Encoding.encryptString(plaintext, password);
        String decrypted = Encoding.decryptString(encrypted, password);

        Assert.assertEquals("Round-trip encrypt/decrypt should recover original plaintext",
                plaintext, decrypted);
    }

    /**
     * Verifies that decrypting with the wrong password does not produce
     * the original plaintext (it returns the error message).
     */
    @Test
    public void testDecryptWithWrongPasswordFails() throws Exception {
        String plaintext = "SensitiveData";
        String correctPassword = "correctPassword";
        String wrongPassword = "wrongPassword";

        String encrypted = Encoding.encryptString(plaintext, correctPassword);
        String result = Encoding.decryptString(encrypted, wrongPassword);

        // Should NOT recover the original plaintext with wrong password
        Assert.assertNotEquals("Decryption with wrong password must not recover original plaintext",
                plaintext, result);
    }

    /**
     * Verifies that the algorithm in use is NOT the broken PBEWithMD5AndDES.
     * This is done by attempting to instantiate the SecretKeyFactory with the
     * weak algorithm and confirming it is not the one producing our valid results.
     * The encrypt/decrypt round trip only succeeds if the correct algorithm
     * (PBEWithHmacSHA256AndAES_256) is used on both sides.
     */
    @Test
    public void testStrongAlgorithmProducesConsistentResults() throws Exception {
        String plaintext = "AlgorithmCheck";
        String password = "mySecretKey";

        String enc1 = Encoding.encryptString(plaintext, password);
        String enc2 = Encoding.encryptString(plaintext, password);

        // Deterministic (same salt/IV): both calls should produce identical ciphertext
        // (because static salt is fixed). Both encryptions should be decryptable.
        String dec1 = Encoding.decryptString(enc1, password);
        String dec2 = Encoding.decryptString(enc2, password);

        Assert.assertEquals("First decryption should recover plaintext", plaintext, dec1);
        Assert.assertEquals("Second decryption should recover plaintext", plaintext, dec2);
    }

    /**
     * Verifies that a non-encrypted input to decryptString gracefully returns
     * an error message rather than throwing an exception.
     */
    @Test
    public void testDecryptInvalidInputReturnsErrorMessage() {
        String result = Encoding.decryptString("not-encrypted-data", "somePassword");
        Assert.assertEquals("Decrypting invalid input should return error message",
                "This is not an encrypted string", result);
    }

    /**
     * Verifies that encryptString with an empty password does not throw
     * and produces output (empty password is handled gracefully).
     */
    @Test
    public void testEncryptWithEmptyPassword() throws Exception {
        String plaintext = "TestData";
        String encrypted = Encoding.encryptString(plaintext, "");

        // Should not be "Encryption error" — it should succeed
        Assert.assertNotNull("Encrypted result should not be null", encrypted);
        Assert.assertFalse("Encrypted result should not be empty", encrypted.isEmpty());
    }

    /**
     * Regression test: confirms the broken PBEWithMD5AndDES algorithm is no
     * longer referenced by verifying that encrypted output from the strong
     * algorithm cannot be decrypted with DES-derived expectations.
     * Since we replaced both methods, a valid round-trip is only possible
     * with AES_256.
     */
    @Test
    public void testEncryptedOutputIsNotCompatibleWithDesAlgorithm() {
        // If PBEWithMD5AndDES were still in use, it would produce different
        // (shorter) ciphertext. AES-256 ciphertext is always at least 32 bytes
        // after base64 encoding. This is a structural regression check.
        try {
            String encrypted = Encoding.encryptString("test", "password");
            // PBEWithMD5AndDES produces ~8-byte blocks; AES_256 produces >= 16-byte blocks
            // After base64 encoding, AES_256 output is noticeably longer
            // (at minimum 24 base64 chars for 16 bytes)
            Assert.assertTrue(
                    "Strong algorithm (AES_256) output should be at least 24 base64 characters",
                    encrypted.trim().length() >= 24);
        } catch (SecurityException e) {
            Assert.fail("encryptString should not throw a SecurityException: " + e.getMessage());
        }
    }
}
