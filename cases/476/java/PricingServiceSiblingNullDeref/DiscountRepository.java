package evalcases;

public interface DiscountRepository {
    // Returns null when no discount is configured for the given sku.
    Long findDiscountCentsForSku(String sku);
}
