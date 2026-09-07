package org.owasp.benchmark.helpers;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;

/** Compile-only stand-in for the OWASP Benchmark utility class. */
public final class Utils {
    public static final String TESTFILES_DIR = "testfiles/";
    private Utils() {}
    public static String getInsecureOSCommandString(String osName) { return "echo"; }
    public static String getInsecureOSCommandString(ClassLoader loader) { return "echo"; }
    public static void printOSCommandResults(Process process, HttpServletResponse response) throws IOException {}
}
