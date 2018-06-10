package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.cloud.model.internal.CloudResource;
import eu.h2020.symbiote.cloud.model.internal.FederatedResource;
import eu.h2020.symbiote.cloud.model.internal.FederationSearchResult;
import eu.h2020.symbiote.model.cim.Resource;
import eu.h2020.symbiote.model.cim.SymbolicLocation;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static eu.h2020.symbiote.security.AbstractADMTestSuite.getCertificateFromTestKeystore;
import static eu.h2020.symbiote.security.AbstractADMTestSuite.getPrivateKeyTestFromKeystore;


/**
 * Dummy REST service mimicking exposed AAM and PlatformRegistry features required by SymbIoTe users.
 *
 * @author Jakub Toczek (PSNC)
 */
@RestController
public class DummyPlatformAAMAndPlatformRegistry {
    private static final String PLATFORM_PATH = "/test/platform";
    private static final String KEYSTORE_AND_CERTIFICATE_PASSWORD = "1234567";
    private static final String PR_PATH = "/pr";
    private static final Log log = LogFactory.getLog(DummyPlatformAAMAndPlatformRegistry.class);
    public boolean returnResource = true;
    public String resourcePlatformId = "testPlatformId";

    //AAM
    @GetMapping(path = PLATFORM_PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE + "/platform/{platformIdentifier}/component/{componentIdentifier}")
    public ResponseEntity<String> getComponentCertificate(String componentIdentifier, String platformIdentifier) throws
            NoSuchAlgorithmException,
            CertificateException,
            IOException,
            NoSuchProviderException,
            KeyStoreException {

        Certificate cert = new Certificate(
                CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                        "keystores/core.p12",
                        KEYSTORE_AND_CERTIFICATE_PASSWORD,
                        "registry-core-1")));

        return new ResponseEntity<>(cert.getCertificateString(), HttpStatus.OK);
    }

    @GetMapping(path = PLATFORM_PATH + PR_PATH + "/list_resources_in_predicate")
    public ResponseEntity<FederationSearchResult> searchResultResponseEntity(@RequestHeader HttpHeaders httpHeaders,
                                                                             @RequestParam(value = "name", required = false) List<String> resourceNames,
                                                                             @RequestParam(value = "description", required = false) List<String> resourceDescriptions,
                                                                             @RequestParam(value = "id", required = false) List<String> symbioteIds,
                                                                             @RequestParam(value = "federationId", required = false) List<String> resourceFederations,
                                                                             @RequestParam(value = "observes_property", required = false) List<String> observes_property,
                                                                             @RequestParam(value = "resource_type", required = false) String resourceType,
                                                                             @RequestParam(value = "location_name", required = false) List<String> locationName,//String locationName,
                                                                             @RequestParam(value = "location_lat", required = false) Double locationLat,
                                                                             @RequestParam(value = "location_long", required = false) Double locationLong,
                                                                             @RequestParam(value = "max_distance", required = false) Double maxDistance,
                                                                             @RequestParam(value = "sort", required = false) String sort
    ) throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        log.info("Received request for search.");
        PrivateKey prPrivateKey = getPrivateKeyTestFromKeystore(
                "keystores/core.p12",
                KEYSTORE_AND_CERTIFICATE_PASSWORD,
                KEYSTORE_AND_CERTIFICATE_PASSWORD,
                "registry-core-1");
        String serviceResponse = MutualAuthenticationHelper.getServiceResponse(prPrivateKey, new Date().getTime());
        FederationSearchResult federationSearchResult = new FederationSearchResult();
        List resources = new ArrayList<FederatedResource>();
        CloudResource cloudResource = new CloudResource();
        cloudResource.setResource(new Resource());
        if (returnResource) {
            FederatedResource federatedResource = new FederatedResource("symbiote@" + resourcePlatformId, cloudResource, "", "", new HashSet<>(), new SymbolicLocation());
            resources.add(federatedResource);
        }
        federationSearchResult.setResources(resources);
        HttpHeaders httpHeaders1 = new HttpHeaders();
        httpHeaders1.add("x-auth-response", serviceResponse);
        return new ResponseEntity<>(federationSearchResult, httpHeaders1, HttpStatus.OK);
    }

}

