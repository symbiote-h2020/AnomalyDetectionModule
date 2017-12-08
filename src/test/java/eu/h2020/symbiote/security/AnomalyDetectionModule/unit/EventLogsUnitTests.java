package eu.h2020.symbiote.security.AnomalyDetectionModule.unit;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

public class EventLogsUnitTests extends AnomalyDetectionModuleApplicationTests {


    @Autowired
    EventManagerService eventManagerService;

    // TODO: Add mocked aamClient

    @Test
    public void loginErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        EventLogRequest eventLogRequest = new EventLogRequest(username, "", "", "12345", EventType.LOGIN_FAILED, 1L, null, null);
        assertFalse(eventLogRepository.exists(username));

        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));
        assertEquals(1, eventLogRepository.findOne(username).getCounter());
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
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, "", "12345", EventType.ACQUISITION_FAILED, 1L, null, null);
        assertFalse(eventLogRepository.exists(username + illegalSign + clientId));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + illegalSign + clientId));
        assertEquals(1, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
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
        EventLogRequest eventLogRequest = new EventLogRequest("", "", "12345", "12345", EventType.VALIDATION_FAILED, 1L, null, null);
        assertFalse(eventLogRepository.exists("12345"));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists("12345"));
        assertEquals(1, eventLogRepository.findOne("12345").getCounter());
//        for (int i = 0; i < 5; i++) {
//            eventManagerService.handleEvent(eventLogRequest);
//        }
//        assertEquals(6, eventLogRepository.findOne("12345").getCounter());
//        eventLogRequest = new EventLogRequest(username, clientId, "12345", "", EventType.VALIDATION_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA, null, null);
//        eventManagerService.handleEvent(eventLogRequest);
//        assertEquals(1, eventLogRepository.findOne("12345").getCounter());
    }

}
