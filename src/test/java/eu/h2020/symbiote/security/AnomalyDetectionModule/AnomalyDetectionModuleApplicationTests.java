package eu.h2020.symbiote.security.AnomalyDetectionModule;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.listeners.amqp.RabbitManager;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
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
    protected EventLogRepository eventLogRepository;
    protected String username = "username";
    protected String clientId = "clientId";
    @Autowired
    protected RabbitManager rabbitManager;
    @Value("${rabbit.queue.event}")
    protected String eventLogQueue;
    protected ObjectMapper mapper = new ObjectMapper();

    @Before
    public void setUp() throws Exception {
        eventLogRepository.deleteAll();
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}
