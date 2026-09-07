package org.owasp.benchmark.helpers;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletResponse;

/** Compile-only stand-in for the OWASP Benchmark database helper. */
public final class DatabaseHelper {
    public static boolean hideSQLErrors = false;
    private DatabaseHelper() {}
    public static Connection getSqlConnection() throws SQLException {
        throw new SQLException("stub: no database in the evaluation harness");
    }
    public static Statement getSqlStatement() throws SQLException {
        throw new SQLException("stub: no database in the evaluation harness");
    }
    public static void printResults(ResultSet results, String sql, HttpServletResponse response) throws IOException {}
    public static void printResults(Object results, String sql, HttpServletResponse response) throws IOException {}
    public static void outputUpdateComplete(String sql, HttpServletResponse response) throws IOException {}
}
