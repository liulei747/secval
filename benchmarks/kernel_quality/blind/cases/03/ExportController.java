package blind.three;

class ExportController {
    private final ExportPolicy policy;
    private final ExportRepository repository;
    ExportController(ExportPolicy policy, ExportRepository repository) {
        this.policy = policy; this.repository = repository;
    }
    byte[] export(long principalId, long tenantId) {
        policy.requireTenantAccess(principalId, tenantId);
        return repository.archive(tenantId);
    }
}

interface ExportPolicy { void requireTenantAccess(long principalId, long tenantId); }
interface ExportRepository { byte[] archive(long tenantId); }
