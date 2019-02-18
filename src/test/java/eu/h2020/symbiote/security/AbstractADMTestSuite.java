package eu.h2020.symbiote.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.IComponentClient;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.services.EventManagerService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMAndPlatformRegistry;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractADMTestSuite {

    protected String serverAddress;
    @Value("${symbIoTe.localaam.url=http://localhost:8443}")
    protected String localAAMAddress;
    @Value("${adm.deployment.owner.username}")
    protected String ADMOwnerUsername;
    @Value("${adm.deployment.owner.password}")
    protected String ADMOwnerPassword;
    @Value("${adm.security.KEY_STORE_PASSWORD}")
    protected String KEY_STORE_PASSWORD;
    @Value("${adm.security.KEY_STORE_FILE_NAME}")
    protected String KEY_STORE_FILE_NAME;


    @Autowired
    protected EventLogRepository eventLogRepository;

    @Autowired
    protected AbuseLogRepository abuseLogRepository;

    @Autowired
    protected AbusePlatformRepository abusePlatformRepository;

    @Autowired
    protected EventManagerService eventManagerService;

    @Autowired
    protected FailedFederatedAccessReportsRepository failedFederatedAccessReportsRepository;
    @Autowired
    protected FederationsRepository federationsRepository;

    @Autowired
    protected DummyCoreAAM dummyCoreAAM;
    @Autowired
    protected DummyPlatformAAMAndPlatformRegistry dummyPlatformAAMAndPlatformRegistry;

    @Value("${rabbit.queue.event}")
    protected String eventLogQueue;
    protected ObjectMapper mapper = new ObjectMapper();

    @LocalServerPort
    protected int port;

    protected String username = "username";
    protected String clientId = "clientId";
    protected String platformId = "12345";
    protected String platformId2 = "23456";
    protected String jti = "9876";

    protected IComponentClient componentClient;
    protected String oldCoreAAMAddress;
    protected String oldTrustManagerAddress;

    @Autowired
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;


    @BeforeClass
    public static void setupSuite() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }


    public static X509Certificate getCertificateFromTestKeystore(String keyStoreName, String keyStorePassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), keyStorePassword.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    public static PrivateKey getPrivateKeyTestFromKeystore(String keyStoreName, String keyStorePassword, String pvKeyPassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), keyStorePassword.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(certificateAlias, pvKeyPassword.toCharArray());
    }

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        dummyCoreAAM.port = port;
        serverAddress = "http://localhost:" + port + SecurityConstants.ADM_PREFIX;
        failedFederatedAccessReportsRepository.deleteAll();
        federationsRepository.deleteAll();
        eventLogRepository.deleteAll();
        abuseLogRepository.deleteAll();
        abusePlatformRepository.deleteAll();

        // finalizing ze mocks
        IComponentSecurityHandler mockedCSH = Mockito.mock(IComponentSecurityHandler.class);
        ISecurityHandler mockedSH = Mockito.mock(ISecurityHandler.class);
        Mockito.when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedCSH);
        Mockito.when(mockedCSH.getSecurityHandler()).thenReturn(mockedSH);
        Mockito.when(mockedSH.getAvailableAAMs(localAAMAddress)).thenReturn(dummyCoreAAM.getAvailableAAMs().getBody().getAvailableAAMs());
    }

    public String convertObjectToJson(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }

}
