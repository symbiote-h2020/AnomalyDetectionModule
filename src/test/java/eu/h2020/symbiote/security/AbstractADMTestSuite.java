package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.repositories.FailedAuthenticationReportRepository;
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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
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
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
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
    FailedAuthenticationReportRepository failedAuthenticationReportRepository;
    @LocalServerPort
    private int port;

    @BeforeClass
    public static void setupSuite() throws Exception {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
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
    public void setUp() {
        // Catch the random port
        serverAddress = "https://localhost:" + port;
        failedAuthenticationReportRepository.deleteAll();
    }

}
