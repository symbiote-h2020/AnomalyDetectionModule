package eu.h2020.symbiote.security.AnomalyDetectionModule.functional;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class EventLogTests extends AnomalyDetectionModuleApplicationTests {

    @Autowired
    RabbitTemplate rabbitTemplate;

    @Test
    public void loginFailLogOverAMQPTestSuccess() throws IOException, WrongCredentialsException {
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, jti, platformId, EventType.LOGIN_FAILED, 0L, null, null);
        assertFalse(eventLogRepository.exists(eventLogRequest.getUsername()));
        rabbitTemplate.convertSendAndReceive(eventLogQueue, mapper.writeValueAsString(eventLogRequest).getBytes());

        assertTrue(eventLogRepository.exists(eventLogRequest.getUsername()));
    }

    @Test
    public void acquisitionFailLogOverAMQPTestSuccess() throws IOException, WrongCredentialsException {
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, jti, platformId, EventType.ACQUISITION_FAILED, 0L, null, null);
        assertFalse(eventLogRepository.exists(eventLogRequest.getUsername() + illegalSign + eventLogRequest.getClientIdentifier()));
        rabbitTemplate.convertSendAndReceive(eventLogQueue, mapper.writeValueAsString(
                eventLogRequest).getBytes());

        assertTrue(eventLogRepository.exists(eventLogRequest.getUsername() + illegalSign + eventLogRequest.getClientIdentifier()));
    }

    @Test
    public void validationFailLogOverAMQPTestSuccess() throws IOException, WrongCredentialsException {
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, jti, platformId, EventType.VALIDATION_FAILED, 0L, null, null);
        assertFalse(eventLogRepository.exists(eventLogRequest.getJti()));
        rabbitTemplate.convertSendAndReceive(eventLogQueue, mapper.writeValueAsString(
                eventLogRequest).getBytes());

        assertTrue(eventLogRepository.exists(eventLogRequest.getJti()));
    }
}
