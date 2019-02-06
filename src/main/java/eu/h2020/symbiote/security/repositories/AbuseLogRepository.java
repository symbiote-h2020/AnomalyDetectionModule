package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface AbuseLogRepository extends MongoRepository<EventLogRequest, String> {

    List<EventLogRequest> getAllByUsername(String username);

    List<EventLogRequest> findAllByPlatformIdAndUsername(String platformId, String username);

    List<EventLogRequest> findAllByPlatformIdAndUsernameAndClientIdentifier(String platformId, String username, String clientIdentifier);
    
}
