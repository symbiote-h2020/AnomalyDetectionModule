package eu.h2020.symbiote.security.AnomalyDetectionModule.functional;

import eu.h2020.symbiote.security.AnomalyDetectionModule.AnomalyDetectionModuleApplicationTests;
import eu.h2020.symbiote.security.AnomalyDetectionModule.utils.DummyAAM;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.ComponentClient;
import eu.h2020.symbiote.security.communication.IComponentClient;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public class AnomalyReportTests extends AnomalyDetectionModuleApplicationTests {

    protected String serverAddress;
    protected IComponentClient componentClient;

    @Autowired
    protected EventManagerService eventManagerService;

    @Autowired
    protected DummyAAM dummyAAM;

    @LocalServerPort
    private int port;

    @Before
    public void setUp() {
        serverAddress = "http://localhost:" + port + "/test/paam";
        componentClient = new ComponentClient(serverAddress);
    }

    @Test
    public void reportAnomalySuccessTest() throws IOException, TimeoutException, WrongCredentialsException, InvalidArgumentsException {

        HandleAnomalyRequest handleAnomalyRequest = new HandleAnomalyRequest("testUser", "", "", EventType.VALIDATION_FAILED, System.currentTimeMillis() + 1000000, 1000000);

        String result = componentClient.reportAnomaly(handleAnomalyRequest);
        assertTrue(Boolean.parseBoolean(result));

    }


}
