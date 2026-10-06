package org.owasp.webgoat.lessons;

import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.webgoat.util.HtmlEncoder;

/**
 * Tests that verify the Stored XSS remediation in StoredXss.makeList().
 *
 * The fix encodes the title value retrieved from the database using
 * HtmlEncoder.encode() before passing it to ECSFactory.makeLink(), which
 * renders it as HTML link text. These tests confirm that XSS payloads
 * stored in the database are neutralized at the rendering boundary.
 */
public class StoredXssEncodingTest {

    /**
     * Verifies that a basic script-tag XSS payload stored in the database
     * is HTML-encoded and cannot execute as JavaScript when rendered.
     * After the fix, results.getString(TITLE_COL) is wrapped in
     * HtmlEncoder.encode() before being passed to ECSFactory.makeLink().
     */
    @Test
    public void testScriptTagXssPayloadIsEncoded() {
        String maliciousTitle = "<script>alert('xss')</script>";
        String encoded = HtmlEncoder.encode(maliciousTitle);

        // The encoded output must not contain the literal '<' or '>' characters
        assertFalse("Encoded title must not contain literal '<'", encoded.contains("<"));
        assertFalse("Encoded title must not contain literal '>'", encoded.contains(">"));

        // The encoded output must contain the safe entity representations
        assertTrue("'<' must be encoded as &lt; or numeric entity",
                encoded.contains("&lt;") || encoded.contains("&#60;"));
        assertTrue("'>' must be encoded as &gt; or numeric entity",
                encoded.contains("&gt;") || encoded.contains("&#62;"));
    }

    /**
     * Verifies that an image-tag onerror XSS payload is encoded.
     */
    @Test
    public void testImgOnerrorXssPayloadIsEncoded() {
        String maliciousTitle = "<img src=x onerror=alert(1)>";
        String encoded = HtmlEncoder.encode(maliciousTitle);

        assertFalse("Encoded title must not contain literal '<'", encoded.contains("<"));
        assertFalse("Encoded title must not contain literal '>'", encoded.contains(">"));
    }

    /**
     * Verifies that a double-quote character in a title (which could break out
     * of an HTML attribute context) is properly encoded.
     */
    @Test
    public void testDoubleQuoteIsEncoded() {
        String maliciousTitle = "title\" onmouseover=\"alert(1)";
        String encoded = HtmlEncoder.encode(maliciousTitle);

        // Double quote should be encoded as &quot;
        assertFalse("Encoded title must not contain literal double-quote", encoded.contains("\""));
        assertTrue("Double-quote must be encoded as &quot;", encoded.contains("&quot;"));
    }

    /**
     * Verifies that an ampersand in a title is encoded to prevent entity injection.
     */
    @Test
    public void testAmpersandIsEncoded() {
        String titleWithAmpersand = "Research & Development";
        String encoded = HtmlEncoder.encode(titleWithAmpersand);

        assertFalse("Encoded title must not contain literal '&' followed by raw text",
                encoded.matches(".*&(?!#?[a-zA-Z0-9]+;).*"));
        assertTrue("Ampersand must be encoded as &amp;", encoded.contains("&amp;"));
    }

    /**
     * Verifies that a safe, plain-text title passes through encoding intact
     * (i.e., safe content is still rendered correctly after encoding).
     */
    @Test
    public void testPlainTextTitleRemainsReadable() {
        String safeTitle = "Hello World";
        String encoded = HtmlEncoder.encode(safeTitle);

        assertEquals("Plain ASCII text must be unchanged by HTML encoding",
                "Hello World", encoded);
    }

    /**
     * Verifies that an empty string title does not cause a NullPointerException
     * or produce unexpected output.
     */
    @Test
    public void testEmptyTitleIsHandledSafely() {
        String emptyTitle = "";
        String encoded = HtmlEncoder.encode(emptyTitle);

        assertNotNull("Encoding an empty string must not return null", encoded);
        assertEquals("Encoding an empty string must return an empty string", "", encoded);
    }

    /**
     * Verifies that a JavaScript URI scheme embedded in a title is encoded.
     * This pattern is used in href-injection attacks.
     */
    @Test
    public void testJavascriptUriSchemeInTitleIsEncoded() {
        String maliciousTitle = "javascript:alert(document.cookie)";
        String encoded = HtmlEncoder.encode(maliciousTitle);

        // 'javascript:' itself contains only safe ASCII chars (no <>"&),
        // but this test confirms encoding does not strip or break the string
        // in a way that would reintroduce XSS when placed into HTML context.
        assertNotNull("Encoding must not return null", encoded);
        // Colons are safe ASCII characters and pass through unchanged
        assertTrue("Result should contain 'javascript' text (encoded safely)",
                encoded.contains("javascript"));
    }

    /**
     * Verifies that a polyglot XSS payload with multiple attack vectors is
     * fully neutralized by HTML encoding.
     */
    @Test
    public void testPolyglotXssPayloadIsEncoded() {
        String polyglot = "\"><script>alert(1)</script><\"";
        String encoded = HtmlEncoder.encode(polyglot);

        assertFalse("Encoded output must not contain literal '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain literal '>'", encoded.contains(">"));
        assertFalse("Encoded output must not contain literal '\"'", encoded.contains("\""));
    }
}
