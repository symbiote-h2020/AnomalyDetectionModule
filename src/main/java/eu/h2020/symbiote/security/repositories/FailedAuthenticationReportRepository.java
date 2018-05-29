package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.FailedAuthenticationReport;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface FailedAuthenticationReportRepository extends MongoRepository<FailedAuthenticationReport, String> {
}
