package eu.h2020.symbiote.security.AnomalyDetectionModule;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.listeners.amqp.RabbitManager;
import eu.h2020.symbiote.security.repositories.AbuseLogRepository;
import eu.h2020.symbiote.security.repositories.AbusePlatformRepository;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
import eu.h2020.symbiote.security.repositories.entities.AbusePlatformEntry;
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

    @Autowired
    protected AbuseLogRepository abuseLogRepository;

    @Autowired
    protected AbusePlatformRepository abusePlatformRepository;

    protected String username = "username";
    protected String clientId = "clientId";
    protected String platformId = "12345";
    protected String platformId2 = "23456";
    protected String jti = "9876";

    @Autowired
    protected RabbitManager rabbitManager;

    @Value("${rabbit.queue.event}")
    protected String eventLogQueue;
    protected ObjectMapper mapper = new ObjectMapper();

    @Before
    public void setUp() throws Exception {
        eventLogRepository.deleteAll();
        abuseLogRepository.deleteAll();
        abusePlatformRepository.deleteAll();
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}
