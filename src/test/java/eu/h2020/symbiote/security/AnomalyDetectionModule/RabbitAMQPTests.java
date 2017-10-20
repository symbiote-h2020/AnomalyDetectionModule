package eu.h2020.symbiote.security.AnomalyDetectionModule;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertTrue;

public class RabbitAMQPTests extends AnomalyDetectionModuleApplicationTests {

    @Test
    public void communicationTest() throws IOException, TimeoutException {
        EventLogRequest eventLogRequest = new EventLogRequest("testUser", "", "", EventType.LOGIN_FAILED, 0L);
        byte[] response = eventLogOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (eventLogRequest).getBytes());
        String ret = mapper.readValue(response, String.class);
        assertTrue("OK".equals(ret));
    }
}
