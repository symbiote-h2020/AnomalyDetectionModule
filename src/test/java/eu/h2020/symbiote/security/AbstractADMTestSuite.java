package eu.h2020.symbiote.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.security.repositories.FailedFederatedAccessReportsRepository;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMAndPlatformRegistry;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@ActiveProfiles("test")
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractADMTestSuite {

    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:http://localhost:8443}")
    protected String coreInterfaceAddress;
    @Value("${adm.deployment.owner.username}")
    protected String ADMOwnerUsername;
    @Value("${adm.deployment.owner.password}")
    protected String ADMOwnerPassword;
    @Value("${adm.security.KEY_STORE_PASSWORD}")
    protected String KEY_STORE_PASSWORD;
    @Value("${adm.security.PV_KEY_PASSWORD}")
    protected String PV_KEY_PASSWORD;
    @Value("${adm.security.KEY_STORE_FILE_NAME}")
    protected String KEY_STORE_FILE_NAME;
    @Value("${adm.security.CERTIFICATE_ALIAS}")
    protected String CERTIFICATE_ALIAS;
    @Autowired
    protected FailedFederatedAccessReportsRepository failedFederatedAccessReportsRepository;
    @Autowired
    protected FederationsRepository federationsRepository;
    @Autowired
    protected DummyCoreAAM dummyCoreAAM;
    @Autowired
    protected DummyPlatformAAMAndPlatformRegistry dummyPlatformAAMAndPlatformRegistry;
    @LocalServerPort
    private int port;

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
        serverAddress = "http://localhost:" + port;
        failedFederatedAccessReportsRepository.deleteAll();
        federationsRepository.deleteAll();
    }

    public String convertObjectToJson(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }

}
