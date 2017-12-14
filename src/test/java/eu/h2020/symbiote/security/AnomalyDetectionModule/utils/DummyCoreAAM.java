package eu.h2020.symbiote.security.AnomalyDetectionModule.utils;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;


@RestController
public class DummyCoreAAM {
    private static final Log log = LogFactory.getLog(DummyAAM.class);
    private static final String PATH = "/test/caam";

    private AvailableAAMsCollection aams = new AvailableAAMsCollection();
    public int port;
    private static final String platformId = "12345";


    public DummyCoreAAM() {
    }


    @GetMapping(path = PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (aams.getAvailableAAMs().isEmpty()) {
            aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("http://localhost:" + port + PATH,
                    SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                    SecurityConstants.CORE_AAM_INSTANCE_ID,
                    new Certificate(), new HashMap<>()));

            aams.getAvailableAAMs().put(platformId, new AAM("http://localhost:" + port + "/test/paam",
                    SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                    platformId,
                    new Certificate(), new HashMap<>()));
        }
        return new ResponseEntity<>(aams, HttpStatus.OK);
    }

}

