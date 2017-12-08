package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.ComponentClient;
import eu.h2020.symbiote.security.communication.IComponentClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

@Service
public class EventManagerService {

    @Value("${adm.environment.coreInterfaceAddress:https://localhost:8443}")
    private String coreInterfaceAddress;

    @Value("${adm.maxFailsNumber}")
    private int maxFailsNumber;

    private EventLogRepository eventLogRepository;
    @Autowired
    EventManagerService(EventLogRepository eventLogRepository) {

        this.eventLogRepository = eventLogRepository;
    }

    public ResponseEntity<String> handleEvent(EventLogRequest eventLogRequest) throws WrongCredentialsException, InvalidArgumentsException {

        EventLog event = null;

        switch (eventLogRequest.getEventType()) {
            case LOGIN_FAILED:
                event = addLoginFailEvent(eventLogRequest);
                break;
            case VALIDATION_FAILED:
                event = addValidationFailEvent(eventLogRequest);
                break;
            case ACQUISITION_FAILED:
                event = addHomeTokenAcquisitionFailEvent(eventLogRequest);
                break;
        }
        assert event != null;
        eventLogRepository.save(event);

        if(event.getCounter()>=maxFailsNumber) {
            AAMClient coreAamClient = ClientFactory.getAAMClient(coreInterfaceAddress);
            HandleAnomalyRequest handleAnomalyRequest = new HandleAnomalyRequest(event.getIdentifier(), "", "", event.getEventType(), System.currentTimeMillis(), 100);
            for(String platformId: event.getPlatformIds()) {
                AAM platform = coreAamClient.getAvailableAAMs().getAvailableAAMs().get(platformId);
                if(platform != null) {
                    String platformAddress = platform.getAamAddress();
                    ComponentClient platformClient = new ComponentClient(platformAddress);
                    platformClient.reportAnomaly(handleAnomalyRequest);
                    event.removePlatformId(platformId);
                }
            }
        }
        return ResponseEntity.status(HttpStatus.OK).body("");
    }

    public EventLog addLoginFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        if (!eventLogRepository.exists(eventLogRequest.getUsername())) {
            event = new EventLog(eventLogRequest.getUsername(), eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.LOGIN_FAILED);
            event.addPlatformId(eventLogRequest.getPlatformId());
        } else {
            event = eventLogRepository.findOne(eventLogRequest.getUsername());
            event.setLastError(eventLogRequest.getTimestamp());
            event.addPlatformId(eventLogRequest.getPlatformId());
        }
        return event;
    }

    public EventLog addHomeTokenAcquisitionFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = buildIdentifier(eventLogRequest);
        if (!eventLogRepository.exists(identifier)) {
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.ACQUISITION_FAILED);
            event.addPlatformId(eventLogRequest.getPlatformId());
        } else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
            event.addPlatformId(eventLogRequest.getPlatformId());
        }
        return event;
    }

    private String buildIdentifier(EventLogRequest eventLogRequest) {
        if (eventLogRequest.getClientIdentifier() == null
                || eventLogRequest.getClientIdentifier().isEmpty())
            return eventLogRequest.getUsername();
        return eventLogRequest.getUsername() + illegalSign + eventLogRequest.getClientIdentifier();
    }

    public EventLog addValidationFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = eventLogRequest.getJti();
        if (!eventLogRepository.exists(identifier)) {
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.VALIDATION_FAILED);
            event.addPlatformId(eventLogRequest.getPlatformId());
        } else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
            event.addPlatformId(eventLogRequest.getPlatformId());
        }
        return event;
    }
}
