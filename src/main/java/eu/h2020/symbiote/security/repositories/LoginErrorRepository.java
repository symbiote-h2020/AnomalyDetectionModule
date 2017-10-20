package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface LoginErrorRepository extends MongoRepository<EventLog, String> {
}