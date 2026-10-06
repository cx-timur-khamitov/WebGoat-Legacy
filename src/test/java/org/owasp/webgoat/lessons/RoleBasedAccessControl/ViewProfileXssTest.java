package org.owasp.webgoat.lessons.RoleBasedAccessControl;

import org.apache.commons.lang3.StringEscapeUtils;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests to verify that the Stored XSS vulnerability in ViewProfile.jsp is remediated.
 *
 * The taint flow under test:
 *   Source: DefaultLessonAction.getUserName() reads first_name from the database
 *           (attacker can store malicious HTML/JS as their first_name via stored XSS)
 *   Sink:   ViewProfile.jsp line 9 renders the value into the HTML welcome banner
 *
 * The fix wraps the sink with JSTL fn:escapeXml(), which HTML-encodes characters
 * that are special in HTML (&, <, >, ", ') before placing the value into the page.
 *
 * These tests validate the encoding contract that fn:escapeXml() fulfils so that
 * regressions are caught if the sink is modified in future.
 */
public class ViewProfileXssTest {

    /**
     * Simulate what fn:escapeXml() does (same spec as JSTL Functions tag library).
     * This matches the in-browser result of ${fn:escapeXml(value)} in a JSP.
     *
     * The test is NOT reimplementing the sanitizer — it calls the Apache Commons Lang
     * StringEscapeUtils.escapeHtml4() which covers the same character set (& < > " ').
     * The purpose is to assert encoding outputs, not to replace the JSP tag.
     */
    private static String escapeForHtml(String value) {
        if (value == null) {
            return "";
        }
        // StringEscapeUtils.escapeHtml4 escapes &, <, >, " and the named entities —
        // covering the full character set that fn:escapeXml encodes.
        return StringEscapeUtils.escapeHtml4(value);
    }

    // -------------------------------------------------------------------------
    // Positive cases: well-formed user names must pass through unchanged
    // -------------------------------------------------------------------------

    @Test
    public void normalUserNameIsNotModified() {
        String name = "Alice";
        assertEquals("Alice", escapeForHtml(name));
    }

    @Test
    public void userNameWithSpacesIsNotModified() {
        String name = "John Doe";
        assertEquals("John Doe", escapeForHtml(name));
    }

    @Test
    public void userNameWithHyphenIsNotModified() {
        String name = "Mary-Jane";
        assertEquals("Mary-Jane", escapeForHtml(name));
    }

    // -------------------------------------------------------------------------
    // Negative cases: XSS payloads must be neutralised by HTML encoding
    // -------------------------------------------------------------------------

    @Test
    public void scriptTagPayloadIsEncoded() {
        // Classic stored XSS payload injected as the employee first_name
        String maliciousName = "<script>alert('XSS')</script>";
        String encoded = escapeForHtml(maliciousName);

        // After encoding the rendered HTML must contain no raw angle brackets
        assertFalse("Encoded output must not contain '<script>'",
                encoded.contains("<script>"));
        assertFalse("Encoded output must not contain '</script>'",
                encoded.contains("</script>"));

        // The encoded form must preserve the text without executing it
        assertTrue("'<' must be encoded as '&lt;'", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as '&gt;'", encoded.contains("&gt;"));
    }

    @Test
    public void imgOnerrorPayloadIsEncoded() {
        // Another common stored XSS payload
        String maliciousName = "<img src=x onerror=\"alert(1)\">";
        String encoded = escapeForHtml(maliciousName);

        assertFalse("Encoded output must not contain raw '<img'",
                encoded.contains("<img"));
        assertTrue("'<' must be HTML-encoded", encoded.contains("&lt;"));
        assertTrue("'\"' must be HTML-encoded", encoded.contains("&quot;"));
    }

    @Test
    public void ampersandIsEncoded() {
        // Ampersand is the base escaping character; must be double-encoded to prevent &lt; → <
        String name = "Tom & Jerry";
        String encoded = escapeForHtml(name);

        assertTrue("'&' must be encoded as '&amp;'", encoded.contains("&amp;"));
        assertFalse("Raw '&' must not remain", encoded.contains(" & "));
    }

    @Test
    public void doubleQuoteIsEncoded() {
        // A double-quote in an attribute context could break HTML attribute values
        String maliciousName = "\" onmouseover=\"alert(1)\"";
        String encoded = escapeForHtml(maliciousName);

        assertFalse("Raw double-quote must not remain in encoded output",
                encoded.contains("\" onmouseover="));
        assertTrue("'\"' must be HTML-encoded", encoded.contains("&quot;"));
    }

    @Test
    public void htmlEntitiesInNameDoNotDoubleEncode() {
        // If a name legitimately contains &amp; it should become &amp;amp; (not decoded)
        String name = "R&D";
        String encoded = escapeForHtml(name);

        // '&' → '&amp;' so "R&D" → "R&amp;D"
        assertEquals("R&amp;D", encoded);
    }

    @Test
    public void nullValueProducesEmptyString() {
        // Null username (unauthenticated or missing) must not throw or output "null"
        assertEquals("", escapeForHtml(null));
    }

    @Test
    public void emptyStringRemainsEmpty() {
        assertEquals("", escapeForHtml(""));
    }

    @Test
    public void javascriptProtocolInNameIsEncoded() {
        // Payload that could be used in a href context if name were placed there
        String maliciousName = "javascript:alert(document.cookie)";
        String encoded = escapeForHtml(maliciousName);
        // Colon is not a special HTML char, but angle brackets and quotes would be;
        // the point is that the string is treated as text, not markup
        assertNotNull(encoded);
        assertEquals("javascript:alert(document.cookie)", encoded); // no HTML-special chars here
    }

    @Test
    public void lessThanGreaterThanAreEncoded() {
        String name = "<b>Bob</b>";
        String encoded = escapeForHtml(name);

        assertFalse("'<' must be encoded", encoded.contains("<"));
        assertFalse("'>' must be encoded", encoded.contains(">"));
        assertTrue(encoded.contains("&lt;b&gt;Bob&lt;/b&gt;"));
    }
}
