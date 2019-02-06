package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractADMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.repositories.entities.AbusePlatformEntry;
import eu.h2020.symbiote.security.repositories.entities.EventLog;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public class EventLogsUnitTests extends AbstractADMTestSuite {

    private EventLogRequest eventLogRequest = null;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        serverAddress = "http://localhost:" + port + SecurityConstants.ADM_PREFIX + "/test/caam";
        dummyCoreAAM.port = port;
        eventLogRequest = new EventLogRequest(username, clientId, jti, "", platformId, EventType.LOGIN_FAILED, 1L, null, null);
        oldCoreAAMAddress = (String) ReflectionTestUtils.getField(eventManagerService, "coreInterfaceAddress");
        oldTrustManagerAddress = (String) ReflectionTestUtils.getField(eventManagerService, "trustManagerAddress");
        ReflectionTestUtils.setField(eventManagerService, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(eventManagerService, "trustManagerAddress", serverAddress);
    }

    @After
    public void tearDown() {
        ReflectionTestUtils.setField(eventManagerService, "coreInterfaceAddress", oldCoreAAMAddress);
        ReflectionTestUtils.setField(eventManagerService, "trustManagerAddress", oldTrustManagerAddress);
    }

    @Test
    public void loginErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.LOGIN_FAILED);
        assertFalse(eventLogRepository.exists(username));

        // log first login_failed abuse
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));
        assertEquals(1, eventLogRepository.findOne(username).getCounter());
        assertEquals(1, abuseLogRepository.getAllByUsername(username).size());
        assertEquals(username, abuseLogRepository.getAllByUsername(username).get(0).getUsername());
        assertTrue(abusePlatformRepository.exists(platformId));
        assertEquals(1, abusePlatformRepository.findOne(platformId).getCounter());

        // log second login_failed abuse
        eventLogRequest.setTimestamp(eventLogRequest.getTimestamp() + 1);
        eventManagerService.handleEvent(eventLogRequest);
        assertEquals(2, abuseLogRepository.getAllByUsername(username).size());
        assertEquals(2, abusePlatformRepository.findOne(platformId).getCounter());
        assertEquals(1, abusePlatformRepository.findAll().size());

        // max fail number exceed
        eventManagerService.handleEvent(eventLogRequest);
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username));
        assertEquals(0, eventLogRepository.findOne(username).getPlatformIds().size());
    }

    @Test(expected = SecurityException.class)
    public void homeTokenAcquisitionErrorTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.ACQUISITION_FAILED);
        assertFalse(eventLogRepository.exists(username + FIELDS_DELIMITER + clientId));
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + FIELDS_DELIMITER + clientId));
        assertEquals(1, eventLogRepository.findOne(username + FIELDS_DELIMITER + clientId).getCounter());

        eventLogRequest.setPlatformId(platformId2);
        eventManagerService.handleEvent(eventLogRequest);
        assertTrue(eventLogRepository.exists(username + FIELDS_DELIMITER + clientId));
        assertEquals(2, eventLogRepository.findOne(username + FIELDS_DELIMITER + clientId).getPlatformIds().size());

        eventLogRequest.setClientIdentifier(null);
        eventManagerService.handleEvent(eventLogRequest);

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

    @Test(expected = SecurityException.class)
    public void unrecognizedEventTypeTest() throws WrongCredentialsException, InvalidArgumentsException {
        eventLogRequest.setEventType(EventType.NULL);
        eventManagerService.handleEvent(eventLogRequest);
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

        // boundary reputation pass
        eventManagerService.handleEvent(eventLogRequest);
        eventManagerService.handleEvent(eventLogRequest);

    }

}
