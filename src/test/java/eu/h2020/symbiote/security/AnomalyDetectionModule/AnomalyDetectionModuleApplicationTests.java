package eu.h2020.symbiote.security.AnomalyDetectionModule;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.listeners.amqp.RabbitManager;
import eu.h2020.symbiote.security.repositories.HomeTokenAcquisitionErrorRepository;
import eu.h2020.symbiote.security.repositories.LoginErrorRepository;
import eu.h2020.symbiote.security.repositories.ValidationErrorRepository;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public abstract class AnomalyDetectionModuleApplicationTests {

    @Autowired
    protected LoginErrorRepository loginErrorRepository;
    @Autowired
    protected HomeTokenAcquisitionErrorRepository homeTokenAcquisitionErrorRepository;
    @Autowired
    protected ValidationErrorRepository validationErrorRepository;
    protected String username = "username";
    protected String clientId = "clientId";
    @Autowired
    protected RabbitManager rabbitManager;
    @Value("${rabbit.queue.event}")
    protected String eventLogQueue;
    protected ObjectMapper mapper = new ObjectMapper();
    protected RpcClient eventLogOverAMQPClient;

    @Before
    public void setUp() throws Exception {
        eventLogOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                eventLogQueue, 5000);
        loginErrorRepository.deleteAll();
        homeTokenAcquisitionErrorRepository.deleteAll();
        validationErrorRepository.deleteAll();

    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}
