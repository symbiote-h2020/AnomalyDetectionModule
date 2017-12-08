package eu.h2020.symbiote.security.AnomalyDetectionModule.functional;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.junit.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertTrue;

public class RabbitAMQPTests extends AnomalyDetectionModuleApplicationTests {

    @Autowired
    RabbitTemplate rabbitTemplate;
    @Value("${rabbit.queue.event}")
    String anomalyDetectionQueue;
    @Test
    public void communicationTest() throws IOException, TimeoutException {
        EventLogRequest eventLogRequest = new EventLogRequest("testUser", "", "", "", EventType.LOGIN_FAILED, 0L, null, null);
        System.out.println(anomalyDetectionQueue);
        rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(
                eventLogRequest));
        assertTrue(true);
        //test always passes, it's created to check, if right info is showed in logs.
    }
}
