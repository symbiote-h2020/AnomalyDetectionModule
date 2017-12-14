package eu.h2020.symbiote.security.AnomalyDetectionModule.functional;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RabbitAMQPTests extends AnomalyDetectionModuleApplicationTests {

    @Autowired
    RabbitTemplate rabbitTemplate;

    @Test
    public void communicationTest() throws IOException, TimeoutException {
        EventLogRequest eventLogRequest = new EventLogRequest(username, clientId, jti, platformId, EventType.LOGIN_FAILED, 0L, null, null);
        System.out.println(eventLogQueue);
        rabbitTemplate.convertAndSend(eventLogQueue, mapper.writeValueAsString(
                eventLogRequest));
        assertTrue(true);
        //test always passes, it's created to check, if right info is showed in logs.
    }
}
