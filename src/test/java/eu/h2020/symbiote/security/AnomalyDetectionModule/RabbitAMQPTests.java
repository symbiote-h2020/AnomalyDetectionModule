package eu.h2020.symbiote.security.AnomalyDetectionModule;

import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertTrue;

public class RabbitAMQPTests extends AnomalyDetectionModuleApplicationTests {

    @Test
    public void communicationTest() throws IOException, TimeoutException {
        byte[] response = eventLogOverAMQPClient.primitiveCall(mapper.writeValueAsString
                ("EventNumber1").getBytes());
        String ret = mapper.readValue(response, String.class);
        assertTrue("Thanks".equals(ret));
    }
}
