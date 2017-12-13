package eu.h2020.symbiote.security.AnomalyDetectionModule.unit;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.repositories.entities.AbusePlatformEntry;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

public class EventLogsUnitTests extends AnomalyDetectionModuleApplicationTests {


    @Autowired
    EventManagerService eventManagerService;

    private EventLogRequest eventLogRequest = null;
    // TODO: Add mocked aamClient

    @Before
    public void setUp() throws Exception {
        super.setUp();
        eventLogRequest = new EventLogRequest(username, clientId, jti, platformId, EventType.LOGIN_FAILED, 1L, null, null);

    }

    @Test
    public void loginErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.LOGIN_FAILED);
        assertFalse(eventLogRepository.exists(username));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));
        assertEquals(1, eventLogRepository.findOne(username).getCounter());
        assertEquals(1, abuseLogRepository.getAllByUsername(username).size());
        assertEquals(username, abuseLogRepository.getAllByUsername(username).get(0).getUsername());
        assertTrue(abusePlatformRepository.exists(platformId));
        assertEquals(1, abusePlatformRepository.findOne(platformId).getCounter());

        eventLogRequest.setTimestamp(eventLogRequest.getTimestamp() + 1);
        eventManagerService.handleEvent(eventLogRequest);
        assertEquals(2, abuseLogRepository.getAllByUsername(username).size());
        assertEquals(2, abusePlatformRepository.findOne(platformId).getCounter());
        assertEquals(1, abusePlatformRepository.findAll().size());


//        for (int i = 0; i < 5; i++) {
//            eventManagerService.addLoginFailEvent(eventLogRequest);
//        }
//        assertEquals(6, eventLogRepository.findOne(username).getCounter());
//        eventLogRequest = new EventLogRequest(username, "", "", "", EventType.LOGIN_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA, null, null);
//        eventManagerService.addLoginFailEvent(eventLogRequest);
//        assertEquals(1, eventLogRepository.findOne(username).getCounter());
    }

    @Test
    public void homeTokenAcquisitionErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.ACQUISITION_FAILED);
        assertFalse(eventLogRepository.exists(username + illegalSign + clientId));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + illegalSign + clientId));
        assertEquals(1, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());

        eventLogRequest.setPlatformId(platformId2);
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + illegalSign + clientId));
        assertEquals(2, eventLogRepository.findOne(username + illegalSign + clientId).getPlatformIds().size());

        eventLogRequest.setClientIdentifier(null);
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));


//        for (int i = 0; i < 5; i++) {
//            eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
//        }
//        assertEquals(6, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
//        eventLogRequest = new EventLogRequest(username, clientId, "", "", EventType.ACQUISITION_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA, null, null);
//        eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
//        assertEquals(1, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
    }

    @Test
    public void validationErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.VALIDATION_FAILED);
        assertFalse(eventLogRepository.exists(jti));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(jti));
        assertEquals(1, eventLogRepository.findOne(jti).getCounter());

        eventLogRequest.setPlatformId(platformId2);
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(jti));
        assertEquals(2, eventLogRepository.findOne(jti).getPlatformIds().size());
//        for (int i = 0; i < 5; i++) {
//            eventManagerService.handleEvent(eventLogRequest);
//        }
//        assertEquals(6, eventLogRepository.findOne("12345").getCounter());
//        eventLogRequest = new EventLogRequest(username, clientId, "12345", "", EventType.VALIDATION_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA, null, null);
//        eventManagerService.handleEvent(eventLogRequest);
//        assertEquals(1, eventLogRepository.findOne("12345").getCounter());
    }

    @Test
    public void abusePlatformEntryTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.LOGIN_FAILED);
        eventManagerService.handleEvent(eventLogRequest);
        AbusePlatformEntry abusePlatformEntry = abusePlatformRepository.findOne(platformId);

        assertEquals(platformId, abusePlatformEntry.getPlatformId());
        assertEquals(1, abusePlatformEntry.getCounter());
        assertEquals(1, abusePlatformEntry.getLastAbuseTimestamp());

        abusePlatformEntry.setPlatformId(platformId2);
        assertEquals(platformId2, abusePlatformEntry.getPlatformId());
        abusePlatformEntry.setCounter(10);
        assertEquals(10, abusePlatformEntry.getCounter());
    }

    @Test
    public void eventLogTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.LOGIN_FAILED);
        eventManagerService.handleEvent(eventLogRequest);
        EventLog eventLog = eventLogRepository.findOne(username);

        assertEquals(1, eventLog.getCounter());
        assertEquals(EventType.LOGIN_FAILED, eventLog.getEventType());
        assertEquals(1, eventLog.getFirstError());
        assertEquals(1, eventLog.getLastError());
        assertEquals(username, eventLog.getIdentifier());
        assertEquals(Arrays.asList(platformId), eventLog.getPlatformIds());
        eventLog.removePlatformId(platformId);
        assertEquals(Arrays.asList(), eventLog.getPlatformIds());

        eventLogRequest.setTimestamp(7000L);
        eventManagerService.handleEvent(eventLogRequest);

        eventLog = eventLogRepository.findOne(username);
        assertEquals(7000L, eventLog.getLastError());

    }

    @Test
    public void platformReputationTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.VALIDATION_FAILED);
        eventManagerService.handleEvent(eventLogRequest);
        eventManagerService.handleEvent(eventLogRequest);
        eventLogRequest.setPlatformId(platformId2);
        eventManagerService.handleEvent(eventLogRequest);
        assert eventManagerService.platformReputation(platformId2) == 2 / 3f;
        assert eventManagerService.platformReputation("non-existing-platform") == 0;

    }

}
