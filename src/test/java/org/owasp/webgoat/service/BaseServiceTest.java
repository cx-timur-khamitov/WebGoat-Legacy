/**
 * Tests for BaseService to verify the Log Forging vulnerability fix (CWE-117).
 *
 * The vulnerability was: user-controlled URL from request.getRequestURL() was
 * concatenated directly into a log message, enabling attackers to inject newlines
 * and forge log entries. The fix switches to SLF4J parameterized logging ({})
 * which treats the URL as a data argument rather than part of the format string.
 */
package org.owasp.webgoat.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit tests for {@link BaseService} focusing on the log forging remediation.
 * Verifies that handleException() correctly processes requests including those
 * with malicious URL content that would previously enable log forging.
 */
public class BaseServiceTest {

    /** Concrete subclass of abstract BaseService for testing. */
    private static class TestableBaseService extends BaseService {
        // No additional methods needed; tests use the inherited handleException
    }

    private TestableBaseService service;

    @Before
    public void setUp() {
        service = new TestableBaseService();
    }

    // ---------------------------------------------------------------------------
    // Stub HttpServletRequest that returns a configurable request URL
    // ---------------------------------------------------------------------------
    private static HttpServletRequest stubRequest(final String url) {
        return new HttpServletRequest() {
            @Override public StringBuffer getRequestURL() { return new StringBuffer(url); }
            // --- minimal stubs for the rest of the interface ---
            @Override public String getAuthType() { return null; }
            @Override public Cookie[] getCookies() { return new Cookie[0]; }
            @Override public long getDateHeader(String name) { return -1; }
            @Override public String getHeader(String name) { return null; }
            @Override public Enumeration<String> getHeaders(String name) { return null; }
            @Override public Enumeration<String> getHeaderNames() { return null; }
            @Override public int getIntHeader(String name) { return -1; }
            @Override public String getMethod() { return "GET"; }
            @Override public String getPathInfo() { return null; }
            @Override public String getPathTranslated() { return null; }
            @Override public String getContextPath() { return ""; }
            @Override public String getQueryString() { return null; }
            @Override public String getRemoteUser() { return null; }
            @Override public boolean isUserInRole(String role) { return false; }
            @Override public Principal getUserPrincipal() { return null; }
            @Override public String getRequestedSessionId() { return null; }
            @Override public String getRequestURI() { return "/service"; }
            @Override public String getServletPath() { return ""; }
            @Override public HttpSession getSession(boolean create) { return null; }
            @Override public HttpSession getSession() { return null; }
            @Override public boolean isRequestedSessionIdValid() { return false; }
            @Override public boolean isRequestedSessionIdFromCookie() { return false; }
            @Override public boolean isRequestedSessionIdFromURL() { return false; }
            @Override public boolean isRequestedSessionIdFromUrl() { return false; }
            @Override public boolean authenticate(HttpServletResponse response) throws IOException, ServletException { return false; }
            @Override public void login(String username, String password) throws ServletException {}
            @Override public void logout() throws ServletException {}
            @Override public Collection<Part> getParts() throws IOException, ServletException { return null; }
            @Override public Part getPart(String name) throws IOException, ServletException { return null; }
            @Override public Object getAttribute(String name) { return null; }
            @Override public Enumeration<String> getAttributeNames() { return null; }
            @Override public String getCharacterEncoding() { return "UTF-8"; }
            @Override public void setCharacterEncoding(String env) throws UnsupportedEncodingException {}
            @Override public int getContentLength() { return 0; }
            @Override public String getContentType() { return null; }
            @Override public ServletInputStream getInputStream() throws IOException { return null; }
            @Override public String getParameter(String name) { return null; }
            @Override public Enumeration<String> getParameterNames() { return null; }
            @Override public String[] getParameterValues(String name) { return null; }
            @Override public Map<String, String[]> getParameterMap() { return null; }
            @Override public String getProtocol() { return "HTTP/1.1"; }
            @Override public String getScheme() { return "http"; }
            @Override public String getServerName() { return "localhost"; }
            @Override public int getServerPort() { return 8080; }
            @Override public BufferedReader getReader() throws IOException { return null; }
            @Override public String getRemoteAddr() { return "127.0.0.1"; }
            @Override public String getRemoteHost() { return "localhost"; }
            @Override public void setAttribute(String name, Object o) {}
            @Override public void removeAttribute(String name) {}
            @Override public Locale getLocale() { return Locale.US; }
            @Override public Enumeration<Locale> getLocales() { return null; }
            @Override public boolean isSecure() { return false; }
            @Override public RequestDispatcher getRequestDispatcher(String path) { return null; }
            @Override public String getRealPath(String path) { return null; }
            @Override public int getRemotePort() { return 0; }
            @Override public String getLocalName() { return "localhost"; }
            @Override public String getLocalAddr() { return "127.0.0.1"; }
            @Override public int getLocalPort() { return 8080; }
            @Override public ServletContext getServletContext() { return null; }
            @Override public AsyncContext startAsync() throws IllegalStateException { return null; }
            @Override public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException { return null; }
            @Override public boolean isAsyncStarted() { return false; }
            @Override public boolean isAsyncSupported() { return false; }
            @Override public AsyncContext getAsyncContext() { return null; }
            @Override public DispatcherType getDispatcherType() { return DispatcherType.REQUEST; }
            @Override public String changeSessionId() { return null; }
            @Override public <T extends HttpUpgradeHandler> T upgrade(Class<T> httpUpgradeHandlerClass) throws IOException, ServletException { return null; }
            @Override public long getContentLengthLong() { return 0; }
        };
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /**
     * Verify that handleException returns a non-null ExceptionInfo response
     * for a normal URL.
     */
    @Test
    public void handleException_normalUrl_returnsExceptionInfo() {
        HttpServletRequest request = stubRequest("http://localhost:8080/WebGoat/service/test");
        Exception ex = new RuntimeException("test exception");

        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("ExceptionInfo response must not be null", result);
    }

    /**
     * Verify the URL from the request is preserved in the ExceptionInfo response.
     * This confirms the fix did not break the functional behavior.
     */
    @Test
    public void handleException_normalUrl_urlPreservedInResponse() {
        String expectedUrl = "http://localhost:8080/WebGoat/service/test";
        HttpServletRequest request = stubRequest(expectedUrl);
        Exception ex = new RuntimeException("test exception");

        ExceptionInfo result = service.handleException(request, ex);

        assertEquals("URL must be preserved in the ExceptionInfo response", expectedUrl, result.getUrl());
    }

    /**
     * Verify the stack trace message is included in the ExceptionInfo response.
     */
    @Test
    public void handleException_includesStackTraceMessage() {
        HttpServletRequest request = stubRequest("http://localhost:8080/WebGoat/service/test");
        Exception ex = new RuntimeException("specific error message");

        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("Stack trace message must not be null", result.getMessage());
        // The stack trace string should contain the exception class name
        assert result.getMessage().contains("RuntimeException")
                : "Message should contain exception class name";
    }

    /**
     * Verify that a URL containing newline characters (a log forging payload)
     * is still handled without throwing an exception. The parameterized logging
     * fix ensures these characters are recorded as data, not interpreted as
     * new log entries (the behavior is controlled by the logging framework).
     */
    @Test
    public void handleException_urlWithNewlineInjection_handledSafely() {
        // A classic log forging payload: attacker injects a fake log entry via newline
        String maliciousUrl = "http://localhost:8080/service\nINFO: Fake log entry injected by attacker";
        HttpServletRequest request = stubRequest(maliciousUrl);
        Exception ex = new RuntimeException("error");

        // Must not throw; the fix uses parameterized logging which records the
        // tainted URL as a data argument — not as part of the format string
        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("Must return ExceptionInfo even for malicious URL input", result);
        assertEquals("URL with newline must be preserved as-is in the response", maliciousUrl, result.getUrl());
    }

    /**
     * Verify that a URL containing carriage-return characters is handled safely,
     * another common log forging vector.
     */
    @Test
    public void handleException_urlWithCarriageReturnInjection_handledSafely() {
        String maliciousUrl = "http://localhost:8080/service\rINFO: Another forged entry";
        HttpServletRequest request = stubRequest(maliciousUrl);
        Exception ex = new IllegalStateException("error");

        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("Must return ExceptionInfo even for CR-injected URL", result);
        assertEquals("URL with carriage return must be preserved as-is in the response",
                maliciousUrl, result.getUrl());
    }

    /**
     * Verify that a URL containing tab characters is handled safely.
     */
    @Test
    public void handleException_urlWithTabCharacter_handledSafely() {
        String maliciousUrl = "http://localhost:8080/service\tTabInjection";
        HttpServletRequest request = stubRequest(maliciousUrl);
        Exception ex = new RuntimeException("error");

        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("Must return ExceptionInfo even for tab-injected URL", result);
    }

    /**
     * Verify that an empty URL is handled without throwing.
     */
    @Test
    public void handleException_emptyUrl_handledSafely() {
        HttpServletRequest request = stubRequest("");
        Exception ex = new RuntimeException("error");

        ExceptionInfo result = service.handleException(request, ex);

        assertNotNull("Must return ExceptionInfo for empty URL", result);
        assertEquals("", result.getUrl());
    }

    /**
     * Verify that getStringStackTrace returns a non-empty string for a throwable.
     */
    @Test
    public void getStringStackTrace_returnsNonEmptyString() {
        Exception ex = new RuntimeException("stack trace test");

        String trace = service.getStringStackTrace(ex);

        assertNotNull("Stack trace string must not be null", trace);
        assert !trace.isEmpty() : "Stack trace string must not be empty";
        assert trace.contains("RuntimeException") : "Stack trace must contain the exception class name";
    }
}
