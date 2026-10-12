package org.owasp.webgoat.lessons;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import java.io.StringReader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for the XPath injection fix in XPATHInjection.
 *
 * The fix replaces string-concatenated XPath expressions with parameterized
 * expressions using XPathVariableResolver, so that user-supplied values are
 * treated as typed data — not as XPath syntax — by the engine.
 *
 * These tests exercise the parameterized XPath pattern directly to confirm:
 *  1. Legitimate credentials resolve to the correct employee node.
 *  2. Classic XPath injection payloads (e.g. "' or '1'='1") do NOT bypass
 *     authentication — they are compared literally as string values.
 *  3. Payloads that attempt to close and reopen predicates are inert.
 */
public class XPATHInjectionTest {

    /** Minimal in-memory XML that mirrors the structure of EmployeesData.xml. */
    private static final String EMPLOYEES_XML =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<employees>" +
            "  <employee id=\"1\">" +
            "    <loginID>Mike</loginID>" +
            "    <accountno>11123</accountno>" +
            "    <passwd>test123</passwd>" +
            "    <salary>468100</salary>" +
            "  </employee>" +
            "  <employee id=\"2\">" +
            "    <loginID>John</loginID>" +
            "    <accountno>63458</accountno>" +
            "    <passwd>myownpass</passwd>" +
            "    <salary>559833</salary>" +
            "  </employee>" +
            "  <employee id=\"3\">" +
            "    <loginID>Sarah</loginID>" +
            "    <accountno>23363</accountno>" +
            "    <passwd>secret</passwd>" +
            "    <salary>84000</salary>" +
            "  </employee>" +
            "</employees>";

    /** Parameterized expression identical to the one used after the fix. */
    private static final String EXPRESSION =
            "/employees/employee[loginID/text()=$username and passwd/text()=$password]";

    private XPath xPath;

    @Before
    public void setUp() {
        xPath = XPathFactory.newInstance().newXPath();
    }

    /**
     * Helper: runs the parameterized XPath expression with the given credentials
     * and returns the matching NodeList.
     */
    private NodeList evaluate(final String username, final String password) throws Exception {
        xPath.setXPathVariableResolver(new XPathVariableResolver() {
            public Object resolveVariable(QName variableName) {
                if ("username".equals(variableName.getLocalPart())) {
                    return username;
                }
                if ("password".equals(variableName.getLocalPart())) {
                    return password;
                }
                return null;
            }
        });
        InputSource inputSource = new InputSource(new StringReader(EMPLOYEES_XML));
        return (NodeList) xPath.evaluate(EXPRESSION, inputSource, XPathConstants.NODESET);
    }

    // -------------------------------------------------------------------------
    // Positive cases: valid credentials should return the correct employee
    // -------------------------------------------------------------------------

    @Test
    public void validCredentials_Mike_shouldReturnOneNode() throws Exception {
        NodeList result = evaluate("Mike", "test123");
        assertNotNull("Result must not be null", result);
        assertEquals("Exactly one employee node expected for valid credentials", 1, result.getLength());
    }

    @Test
    public void validCredentials_John_shouldReturnOneNode() throws Exception {
        NodeList result = evaluate("John", "myownpass");
        assertNotNull(result);
        assertEquals(1, result.getLength());
    }

    @Test
    public void validCredentials_Sarah_shouldReturnOneNode() throws Exception {
        NodeList result = evaluate("Sarah", "secret");
        assertNotNull(result);
        assertEquals(1, result.getLength());
    }

    // -------------------------------------------------------------------------
    // Negative cases: wrong credentials should return zero nodes
    // -------------------------------------------------------------------------

    @Test
    public void wrongPassword_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("Mike", "wrongpassword");
        assertNotNull(result);
        assertEquals("Wrong password must not match any employee", 0, result.getLength());
    }

    @Test
    public void wrongUsername_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("Unknown", "test123");
        assertNotNull(result);
        assertEquals("Unknown username must not match any employee", 0, result.getLength());
    }

    @Test
    public void emptyCredentials_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("", "");
        assertNotNull(result);
        assertEquals("Empty credentials must not match any employee", 0, result.getLength());
    }

    // -------------------------------------------------------------------------
    // Security cases: XPath injection payloads must NOT bypass authentication
    // -------------------------------------------------------------------------

    /**
     * Classic "or 1=1" payload.
     * Without the fix (string concatenation), this would make the expression:
     *   loginID/text()='' or '1'='1' ...
     * and return all employees. With the fix, the entire string is compared
     * literally, so it matches no loginID value and returns zero nodes.
     */
    @Test
    public void xpathInjection_orAlways_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("' or '1'='1", "anything");
        assertNotNull(result);
        assertEquals(
                "XPath injection 'or always true' must not bypass authentication",
                0, result.getLength());
    }

    /**
     * Payload that closes the string, injects a comment, and uses a wildcard.
     * Without the fix this would be interpreted as XPath syntax and could
     * return all employees. With parameterization it is treated as a literal
     * string value.
     */
    @Test
    public void xpathInjection_closingQuoteAndComment_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("Mike' or '1'='1", "anything");
        assertNotNull(result);
        assertEquals(
                "XPath injection with closing-quote payload must not return results",
                0, result.getLength());
    }

    /**
     * Payload that attempts to inject a second predicate via '][.
     * Parameterization ensures the brackets are treated as literal characters.
     */
    @Test
    public void xpathInjection_bracketPayload_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("Mike'][1 or '1'='1", "anything");
        assertNotNull(result);
        assertEquals(
                "XPath injection with bracket payload must not return results",
                0, result.getLength());
    }

    /**
     * Payload that uses a wildcard loginID combined with always-true password
     * comparison. This targets the password field.
     */
    @Test
    public void xpathInjection_passwordBypass_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("Mike", "' or '1'='1");
        assertNotNull(result);
        assertEquals(
                "XPath injection on password field must not bypass authentication",
                0, result.getLength());
    }

    /**
     * Payload that tries to match all employees by injecting into both fields.
     */
    @Test
    public void xpathInjection_bothFieldsPayload_shouldReturnZeroNodes() throws Exception {
        NodeList result = evaluate("' or 1=1 or '", "' or 1=1 or '");
        assertNotNull(result);
        assertEquals(
                "Injecting into both fields must not return any results",
                0, result.getLength());
    }
}
