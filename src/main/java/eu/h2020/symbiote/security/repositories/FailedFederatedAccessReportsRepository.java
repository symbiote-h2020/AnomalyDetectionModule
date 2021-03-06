package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.FailedFederatedAccessReport;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface FailedFederatedAccessReportsRepository extends MongoRepository<FailedFederatedAccessReport, String> {
}
