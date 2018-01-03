package eu.h2020.symbiote.security.AnomalyDetectionModule;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.AnomalyDetectionModule.utils.DummyAAM;
import eu.h2020.symbiote.security.AnomalyDetectionModule.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.communication.IComponentClient;
import eu.h2020.symbiote.security.repositories.AbuseLogRepository;
import eu.h2020.symbiote.security.repositories.AbusePlatformRepository;
import eu.h2020.symbiote.security.repositories.EventLogRepository;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public abstract class AnomalyDetectionModuleApplicationTests {

    @Autowired
    protected EventLogRepository eventLogRepository;

    @Autowired
    protected AbuseLogRepository abuseLogRepository;

    @Autowired
    protected AbusePlatformRepository abusePlatformRepository;

    @Autowired
    protected EventManagerService eventManagerService;

    protected String username = "username";
    protected String clientId = "clientId";
    protected String platformId = "12345";
    protected String platformId2 = "23456";
    protected String jti = "9876";

    protected String serverAddress;
    protected IComponentClient componentClient;
    protected String oldCoreAAMAddress;
    protected String oldTrustManagerAddress;

    @Autowired
    protected DummyCoreAAM dummyCoreAAM;

    @Autowired
    protected DummyAAM dummyAAM;

    @Value("${rabbit.queue.event}")
    protected String eventLogQueue;
    protected ObjectMapper mapper = new ObjectMapper();

    @LocalServerPort
    protected int port;

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
