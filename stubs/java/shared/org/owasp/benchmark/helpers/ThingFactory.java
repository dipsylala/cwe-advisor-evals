package org.owasp.benchmark.helpers;

public final class ThingFactory {
    private ThingFactory() {}
    public static ThingInterface createThing() { return param -> param; }
}
