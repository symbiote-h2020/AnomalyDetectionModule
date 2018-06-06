package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.unit.FailedAuthorizationUnitTests;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;


/**
 * Dummy REST service mimicking exposed AAM features required by SymbIoTe users and reachable via CoreInterface in
 * the Core and Interworking Interfaces on Platforms' side.
 *
 * @author Jakub Toczek (PSNC)
 */
@RestController
public class DummyCoreAAM {
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/keystores/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String AAM_PATH = "/test/caam";
    public int port;
    public boolean provideSearchOriginPlatform = true;
    private Certificate coreCert;

    public DummyCoreAAM() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("core-1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        coreCert = new Certificate(signedCertificatePEMDataStringWriter.toString());
    }

    @GetMapping(path = AAM_PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() {
        AvailableAAMsCollection aams = new AvailableAAMsCollection(new HashMap<>());
        aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("https://localhost:" + port + AAM_PATH,
                SecurityConstants.CORE_AAM_INSTANCE_ID, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                coreCert, new HashMap<>()));
        //adding any cert as platform one
        if (provideSearchOriginPlatform)
            aams.getAvailableAAMs().put(FailedAuthorizationUnitTests.searchOriginPlatformId,
                    new AAM("https://localhost:" + port + "/test/platform",
                            FailedAuthorizationUnitTests.searchOriginPlatformId,
                            FailedAuthorizationUnitTests.searchOriginPlatformId,
                            coreCert,
                            new HashMap<>())
            );

        return new ResponseEntity<>(aams, HttpStatus.OK);
    }

}

