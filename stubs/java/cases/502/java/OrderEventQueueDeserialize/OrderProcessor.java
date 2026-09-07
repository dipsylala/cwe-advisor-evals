package evalcases;


/** Compile-only collaborator the fixture references but does not ship. */
public interface OrderProcessor {
    void handle(OrderEvent event);
}
