package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

@Service
public class EventManagerService {

    private EventLogRepository eventLogRepository;
    @Autowired
    EventManagerService(EventLogRepository eventLogRepository) {

        this.eventLogRepository = eventLogRepository;
    }

    public void addLoginFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        if (!eventLogRepository.exists(eventLogRequest.getUsername())) {
            event = new EventLog(eventLogRequest.getUsername(), eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.LOGIN_FAILED);
        } else {
            event = eventLogRepository.findOne(eventLogRequest.getUsername());
            event.setLastError(eventLogRequest.getTimestamp());
        }
        eventLogRepository.save(event);
    }

    public void addHomeTokenAcquisitionFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = buildIdentifier(eventLogRequest);
        if (!eventLogRepository.exists(identifier)) {
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.ACQUISITION_FAILED);
        } else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
        }
        eventLogRepository.save(event);
    }

    private String buildIdentifier(EventLogRequest eventLogRequest) {
        if (eventLogRequest.getClientIdentifier() == null
                || eventLogRequest.getClientIdentifier().isEmpty())
            return eventLogRequest.getUsername();
        return eventLogRequest.getUsername() + illegalSign + eventLogRequest.getClientIdentifier();
    }

    public void addValidationFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = eventLogRequest.getJti();
        if (!eventLogRepository.exists(identifier)) {
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.VALIDATION_FAILED);
        } else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
        }
        eventLogRepository.save(event);
    }
}
