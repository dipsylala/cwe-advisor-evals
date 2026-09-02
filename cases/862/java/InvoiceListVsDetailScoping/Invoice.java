package cases.authorization;

public record Invoice(Long id, String ownerUsername, double amount) {
}
