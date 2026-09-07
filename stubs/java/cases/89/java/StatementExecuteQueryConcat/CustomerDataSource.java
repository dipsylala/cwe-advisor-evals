package com.example.customers;


import java.sql.Connection;
import java.sql.SQLException;

/** Compile-only collaborator the fixture references but does not ship. */
public interface CustomerDataSource {
    Connection getConnection() throws SQLException;
}
