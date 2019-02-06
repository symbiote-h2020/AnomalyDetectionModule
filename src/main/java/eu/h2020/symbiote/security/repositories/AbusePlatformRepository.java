package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.AbusePlatformEntry;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface AbusePlatformRepository extends MongoRepository<AbusePlatformEntry, String> {
}
