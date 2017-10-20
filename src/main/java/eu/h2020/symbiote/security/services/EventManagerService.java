package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.repositories.HomeTokenAcquisitionErrorRepository;
import eu.h2020.symbiote.security.repositories.LoginErrorRepository;
import eu.h2020.symbiote.security.repositories.ValidationErrorRepository;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

@Service
public class EventManagerService {

    private LoginErrorRepository loginErrorRepository;
    private HomeTokenAcquisitionErrorRepository homeTokenAcquisitionErrorRepository;
    private ValidationErrorRepository validationErrorRepository;

    @Autowired
    EventManagerService(LoginErrorRepository loginErrorRepository, HomeTokenAcquisitionErrorRepository homeTokenAcquisitionErrorRepository, ValidationErrorRepository validationErrorRepository) {

        this.loginErrorRepository = loginErrorRepository;
        this.homeTokenAcquisitionErrorRepository = homeTokenAcquisitionErrorRepository;
        this.validationErrorRepository = validationErrorRepository;

    }

    public void addLoginFailEvent(EventLogRequest anomalyDetectionRequest) {
        EventLog event;
        if (!loginErrorRepository.exists(anomalyDetectionRequest.getUsername())) {
            event = new EventLog(anomalyDetectionRequest.getUsername(), anomalyDetectionRequest.getTimestamp());
        } else {
            event = loginErrorRepository.findOne(anomalyDetectionRequest.getUsername());
            event.setLastError(anomalyDetectionRequest.getTimestamp());
        }
        loginErrorRepository.save(event);
    }

    public void addHomeTokenAcquisitionFailEvent(EventLogRequest anomalyDetectionRequest) {
        EventLog event;
        String identifier = buildIdentifier(anomalyDetectionRequest);
        if (!homeTokenAcquisitionErrorRepository.exists(identifier)) {
            event = new EventLog(identifier, anomalyDetectionRequest.getTimestamp());
        } else {
            event = homeTokenAcquisitionErrorRepository.findOne(identifier);
            event.setLastError(anomalyDetectionRequest.getTimestamp());
        }
        homeTokenAcquisitionErrorRepository.save(event);
    }

    private String buildIdentifier(EventLogRequest anomalyDetectionRequest) {
        if (anomalyDetectionRequest.getClientIdentifier() == null
                || anomalyDetectionRequest.getClientIdentifier().isEmpty())
            return anomalyDetectionRequest.getUsername();
        return anomalyDetectionRequest.getUsername() + illegalSign + anomalyDetectionRequest.getClientIdentifier();
    }

    public void addValidationFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = eventLogRequest.getJti();
        if (!validationErrorRepository.exists(identifier)) {
            event = new EventLog(identifier, eventLogRequest.getTimestamp());
        } else {
            event = validationErrorRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
        }
        validationErrorRepository.save(event);
    }
}
