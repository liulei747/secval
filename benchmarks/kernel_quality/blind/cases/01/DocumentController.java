package blind.one;

class DocumentController {
    private final DocumentService service;
    DocumentController(DocumentService service) { this.service = service; }
    String download(long principalId, long documentId) { return service.download(principalId, documentId); }
}

class DocumentService {
    private final DocumentRepository repository;
    DocumentService(DocumentRepository repository) { this.repository = repository; }
    String download(long principalId, long documentId) { return repository.content(documentId); }
}

interface DocumentRepository { String content(long documentId); }
