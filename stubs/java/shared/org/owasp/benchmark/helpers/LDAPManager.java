package org.owasp.benchmark.helpers;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/** Compile-only stand-in for the OWASP Benchmark LDAP helper. */
public class LDAPManager {
    public DirContext getDirContext() throws NamingException {
        throw new NamingException("stub: no directory in the evaluation harness");
    }
    public void closeDirContext() {}
}
