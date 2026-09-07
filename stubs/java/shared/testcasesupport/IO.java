package testcasesupport;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Logger;

/** Compile-only stand-in for the Juliet test suite's IO helper. */
public final class IO {
    public static final Logger logger = Logger.getLogger("testcasesupport");
    private IO() {}
    public static void writeLine(String line) { System.out.println(line); }
    public static void writeLine(int value) { System.out.println(value); }
    public static void writeLine(long value) { System.out.println(value); }
    public static Connection getDBConnection() throws SQLException {
        throw new SQLException("stub: no database in the evaluation harness");
    }
}
