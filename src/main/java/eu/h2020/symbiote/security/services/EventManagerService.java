package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.ComponentClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.repositories.AbuseLogRepository;
import eu.h2020.symbiote.security.repositories.AbusePlatformRepository;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
import eu.h2020.symbiote.security.repositories.entities.AbusePlatformEntry;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

@Service
public class EventManagerService {

    @Value("${adm.environment.coreInterfaceAddress:https://localhost:8443}")
    private String coreInterfaceAddress;

    @Value("${adm.environment.trustManagerAddress}")
    private String trustManagerAddress;

    @Value("${adm.maxFailsNumber}")
    private int maxFailsNumber;

    @Value("${adm.platform.reputation}")
    private float boundaryReputation;

    private static Log log = LogFactory.getLog(EventManagerService.class);
    @Autowired
    private EventLogRepository eventLogRepository;
    @Autowired
    private AbuseLogRepository abuseLogRepository;
    @Autowired
    private AbusePlatformRepository abusePlatformRepository;

    /**
     * Method used to handle incoming abuse event
     *
     * @param eventLogRequest request describing event
     */

    public ResponseEntity<String> handleEvent(EventLogRequest eventLogRequest) throws WrongCredentialsException, InvalidArgumentsException, AssertionError {

        EventLog event;

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
            default:
                String msg = "Event type of AnomalyDetectionRequest unrecognized";
                throw new SecurityException(msg);
        }
        assert event != null;


        event.addPlatformId(eventLogRequest.getPlatformId());
        eventLogRepository.save(event);
        abuseLogRepository.save(eventLogRequest);

        this.extendAbusePlatformRepository(eventLogRequest);
        String selectedPlatformId = eventLogRequest.getPlatformId();
        float platformReputation = this.platformReputation(selectedPlatformId);
        if (platformReputation > boundaryReputation) {
            ComponentClient componentClient = new ComponentClient(trustManagerAddress);
            componentClient.reportLowPlatformReputation(selectedPlatformId);
        }
        if (event.getCounter() >= maxFailsNumber) {
            IAAMClient coreAamClient = new AAMClient(coreInterfaceAddress);
            HandleAnomalyRequest handleAnomalyRequest = new HandleAnomalyRequest(event.getIdentifier(), event.getEventType(), System.currentTimeMillis(), 60000);
            List<String> platformIds = new ArrayList<>(event.getPlatformIds());
            Map<String, AAM> availableAAMs;
            try {
                availableAAMs = coreAamClient.getAvailableAAMs().getAvailableAAMs();
            } catch (AAMException e) {
                log.error("Couldn't establish connection with core AAM");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("");
            }
            for (String platformId : platformIds) {
                AAM platform = availableAAMs.get(platformId);
                if (platform != null) {
                    String platformAddress = platform.getAamAddress();
                    ComponentClient platformClient = new ComponentClient(platformAddress);
                    platformClient.reportAnomaly(handleAnomalyRequest);
                    event.removePlatformId(platformId);
                    eventLogRepository.save(event);
                }
            }
            if (eventLogRequest.getSourcePlatformId() != null) {
                AAM sourcePlatform = availableAAMs.get(eventLogRequest.getSourcePlatformId());
                if(sourcePlatform != null) {
                    ComponentClient sourcePlatformClient = new ComponentClient(sourcePlatform.getAamAddress());
                    sourcePlatformClient.notifySourceAAM(handleAnomalyRequest);
                }
            }


        }
        return ResponseEntity.status(HttpStatus.OK).body("");
    }

    private EventLog addLoginFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        if (eventLogRequest.getUsername() == null || eventLogRequest.getUsername().isEmpty()) {
            throw new IllegalArgumentException();
        }
        if (!eventLogRepository.exists(eventLogRequest.getUsername()))
            event = new EventLog(eventLogRequest.getUsername(), eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.LOGIN_FAILED);
        else {
            event = eventLogRepository.findOne(eventLogRequest.getUsername());
            event.setLastError(eventLogRequest.getTimestamp());
        }
        return event;
    }

    private EventLog addHomeTokenAcquisitionFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        String identifier = buildIdentifier(eventLogRequest);
        if (!eventLogRepository.exists(identifier))
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.ACQUISITION_FAILED);
        else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
        }
        return event;
    }

    private EventLog addValidationFailEvent(EventLogRequest eventLogRequest) {
        EventLog event;
        if (eventLogRequest.getJti() == null || eventLogRequest.getJti().isEmpty()) {
            throw new IllegalArgumentException();
        }
        String identifier = eventLogRequest.getJti();
        if (!eventLogRepository.exists(identifier))
            event = new EventLog(identifier, eventLogRequest.getTimestamp(), eventLogRequest.getTimestamp(), EventType.VALIDATION_FAILED);
        else {
            event = eventLogRepository.findOne(identifier);
            event.setLastError(eventLogRequest.getTimestamp());
        }
        return event;
    }

    private String buildIdentifier(EventLogRequest eventLogRequest) {
        if (eventLogRequest.getComponentId() != null && eventLogRequest.getPlatformId() != null &&
                !eventLogRequest.getComponentId().isEmpty() && !eventLogRequest.getPlatformId().isEmpty()) {
            return eventLogRequest.getPlatformId() + illegalSign + eventLogRequest.getComponentId();
        }
        if (eventLogRequest.getUsername() != null && eventLogRequest.getClientIdentifier() != null &&
                !eventLogRequest.getUsername().isEmpty() && !eventLogRequest.getClientIdentifier().isEmpty()) {
            return eventLogRequest.getUsername() + illegalSign + eventLogRequest.getClientIdentifier();
        }
        throw new SecurityException("Wrong data in EventLogRequest.");
    }

    private void extendAbusePlatformRepository(EventLogRequest eventLogRequest) {

        AbusePlatformEntry abusePlatformEntry = abusePlatformRepository.findOne(eventLogRequest.getPlatformId());
        if (abusePlatformEntry != null)
            abusePlatformEntry.setLastAbuseTimestamp(eventLogRequest.getTimestamp());
        else
            abusePlatformEntry = new AbusePlatformEntry(eventLogRequest.getPlatformId(), eventLogRequest.getTimestamp());

        abusePlatformRepository.save(abusePlatformEntry);
    }

    /**
     * Calculates reputation as ratio of entries for platform specified in param to average of all platform entries.
     *
     * @param platformId identifier of platform to check reputation
     * @author Piotr Jakubowski (PSNC)
     */
    public float platformReputation(String platformId) {

        if (!abusePlatformRepository.exists(platformId))
            return 0;
        int sumEntries = 0;
        AbusePlatformEntry selectedPlatform = abusePlatformRepository.findOne(platformId);
        List<AbusePlatformEntry> platformList = abusePlatformRepository.findAll();
        for (AbusePlatformEntry platform : platformList) {
            sumEntries += platform.getCounter();
        }
        return selectedPlatform.getCounter() / (sumEntries / (float) platformList.size());
    }


}
