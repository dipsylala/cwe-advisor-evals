package cases.authorization;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
