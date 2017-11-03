package eu.h2020.symbiote.security.AnomalyDetectionModule.unit;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

public class EventLogsUnitTests extends AnomalyDetectionModuleApplicationTests {


    @Autowired
    EventManagerService eventManagerService;

    @Test
    public void loginErrorTest() {
        EventLogRequest eventLogRequest = new EventLogRequest(username, "", "", EventType.LOGIN_FAILED, 1L);
        assertFalse(eventLogRepository.exists(username));

        eventManagerService.addLoginFailEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));
        assertEquals(1, eventLogRepository.findOne(username).getCounter());
        for (int i = 0; i < 5; i++) {
            eventManagerService.addLoginFailEvent(eventLogRequest);
        }
        assertEquals(6, eventLogRepository.findOne(username).getCounter());
        eventLogRequest = new EventLogRequest(username, "", "", EventType.LOGIN_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA);
        eventManagerService.addLoginFailEvent(eventLogRequest);
        assertEquals(1, eventLogRepository.findOne(username).getCounter());
    }

    @Test
    public void homeTokenAcquisitionErrorTest() {
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, "", EventType.ACQUISITION_FAILED, 1L);
        assertFalse(eventLogRepository.exists(username + illegalSign + clientId));
        eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + illegalSign + clientId));
        assertEquals(1, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
        for (int i = 0; i < 5; i++) {
            eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
        }
        assertEquals(6, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
        eventLogRequest = new EventLogRequest(username, clientId, "", EventType.ACQUISITION_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA);
        eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
        assertEquals(1, eventLogRepository.findOne(username + illegalSign + clientId).getCounter());
    }

    @Test
    public void validationErrorTest() {
        EventLogRequest eventLogRequest = new EventLogRequest("", "", "12345", EventType.VALIDATION_FAILED, 1L);
        assertFalse(eventLogRepository.exists("12345"));
        eventManagerService.addValidationFailEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists("12345"));
        assertEquals(1, eventLogRepository.findOne("12345").getCounter());
        for (int i = 0; i < 5; i++) {
            eventManagerService.addValidationFailEvent(eventLogRequest);
        }
        assertEquals(6, eventLogRepository.findOne("12345").getCounter());
        eventLogRequest = new EventLogRequest(username, clientId, "12345", EventType.VALIDATION_FAILED, 2L + SecurityConstants.ANOMALY_DETECTION_DELTA);
        eventManagerService.addValidationFailEvent(eventLogRequest);
        assertEquals(1, eventLogRepository.findOne("12345").getCounter());
    }

}
