package cases.authorization;

import java.util.List;
import java.util.Optional;

public class InvoiceRepository {
    public Optional<Invoice> findByIdAndOwnerUsername(Long id, String ownerUsername) {
        return Optional.empty();
    }

    public List<Invoice> findByOwnerUsername(String ownerUsername) {
        return List.of();
    }

    public List<Invoice> findAll() {
        return List.of();
    }
}
