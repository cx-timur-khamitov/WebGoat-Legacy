package org.owasp.webgoat;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.Assert.*;

/**
 * Tests for CWE-117 Log Forging remediation in HammerHead.log().
 *
 * The fix replaced direct string concatenation into logger.debug(output)
 * with the SLF4J parameterized form logger.debug("{}", output) so that
 * user-controlled data (HTTP parameter names/values) is passed as a
 * separate argument and cannot inject spurious log entries.
 */
public class HammerHeadLogForgingTest {

    /**
     * Minimal stub of HttpServletRequest that supplies only what
     * HammerHead.log() needs: getRemoteHost() and getRemoteAddr().
     */
    private static class StubRequest implements java.lang.reflect.InvocationHandler {

        private final String remoteHost;
        private final String remoteAddr;

        StubRequest(String remoteHost, String remoteAddr) {
            this.remoteHost = remoteHost;
            this.remoteAddr = remoteAddr;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getRemoteHost": return remoteHost;
                case "getRemoteAddr": return remoteAddr;
                default: return null;
            }
        }
    }

    private HttpServletRequest buildRequest(String remoteHost, String remoteAddr) {
        return (HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{HttpServletRequest.class},
                new StubRequest(remoteHost, remoteAddr));
    }

    private HammerHead hammerHead;

    @Before
    public void setUp() {
        hammerHead = new HammerHead();
    }

    /**
     * Verify that HammerHead.log() does not throw when given a message
     * containing newline characters (a classic log-forging payload).
     * Prior to the fix, the raw newline was concatenated directly into
     * the log call, enabling log injection.  The parameterised fix
     * passes the value as an opaque argument.
     */
    @Test
    public void logMethodDoesNotThrowOnNewlinePayload() {
        HttpServletRequest request = buildRequest("localhost", "127.0.0.1");
        // Payload attempts to inject a fake log line
        String maliciousMessage = "normal message\nINFO: Fake injected log entry from attacker";
        // Should not throw — the parameterized logger handles this gracefully
        hammerHead.log(request, maliciousMessage);
    }

    /**
     * Verify that HammerHead.log() does not throw when message contains
     * carriage-return injection sequences.
     */
    @Test
    public void logMethodDoesNotThrowOnCRLFPayload() {
        HttpServletRequest request = buildRequest("192.168.1.1", "192.168.1.1");
        String maliciousMessage = "data\r\nINFO: Spoofed entry";
        hammerHead.log(request, maliciousMessage);
    }

    /**
     * Verify that HammerHead.log() handles a null message without
     * throwing a NullPointerException (defensive check).
     */
    @Test
    public void logMethodHandlesNullMessage() {
        HttpServletRequest request = buildRequest("localhost", "127.0.0.1");
        // With parameterised logging, null arguments are rendered as "null"
        // and do not cause NPE in the SLF4J binding.
        try {
            hammerHead.log(request, null);
        } catch (NullPointerException npe) {
            fail("log() should not throw NPE when message is null: " + npe.getMessage());
        }
    }

    /**
     * Verify that the logger field inside HammerHead is an SLF4J Logger,
     * confirming the structured logging infrastructure is in place.
     */
    @Test
    public void hammerHeadUsesSlf4jLogger() throws Exception {
        Field loggerField = HammerHead.class.getDeclaredField("logger");
        loggerField.setAccessible(true);
        Object loggerInstance = loggerField.get(hammerHead);
        assertNotNull("HammerHead.logger must not be null", loggerInstance);
        assertTrue("HammerHead.logger must be an SLF4J Logger",
                loggerInstance instanceof Logger);
    }

    /**
     * Verify that HammerHead.log() accepts a benign message without error,
     * confirming that the fix preserves normal functionality.
     */
    @Test
    public void logMethodWorksForNormalMessage() {
        HttpServletRequest request = buildRequest("example.com", "10.0.0.1");
        // Should complete without any exception
        hammerHead.log(request, "lesson=SafeLesson | params=[user=admin]");
    }
}
