package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractADMTestSuite;
import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.entities.FederatedAccessAnomaly;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService.AP_NAME;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

public class FailedAuthorizationUnitTests extends AbstractADMTestSuite {

    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String localPlatformId = "testLocalPlatformId";
    private String federatedPlatformId = "testPlatformId";
    private String federationId = "testFederationId";
    private String resourceId = "testResourceId";
    private long timestamp = 100l;
    @Autowired
    private FailedFederatedAccessReportingService failedFederatedAccessReportingService;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        //mocking component security handler
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        Set<String> set = new HashSet<>();
        set.add(AP_NAME);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(set);
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(new HashSet<>(), 0));
        when(mockedComponentSecurityHandler.isReceivedServiceResponseVerified(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        ReflectionTestUtils.setField(failedFederatedAccessReportingService, "coreInterfaceAddress", serverAddress + "/test/caam");

        ECDSAHelper.enableECDSAProvider();

        //saving federation
        Federation federation = new Federation();
        List<FederationMember> federationMembers = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(federatedPlatformId);
        federationMembers.add(federationMember);
        FederationMember federationMember2 = new FederationMember();
        federationMember2.setPlatformId(localPlatformId);
        federationMembers.add(federationMember2);
        federation.setMembers(federationMembers);
        federation.setId(federationId);
        federationsRepository.save(federation);

        //dummy core, platform aam and pr settings
        dummyPlatformAAMAndPlatformRegistry.returnResource = true;
        dummyCoreAAM.provideLocalPlatform = true;
        dummyPlatformAAMAndPlatformRegistry.resourcePlatformId = federatedPlatformId;
    }

    @Test
    public void reportFailedFederationAuthorizationTestSuccessNewDBEntry() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        //component SH mocked to return true in SecurityRequest check
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.OK, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        //DB check if new report added
        assertEquals(1, failedAuthenticationReportRepository.count());
        FederatedAccessAnomaly federatedAccessAnomalyDB = failedAuthenticationReportRepository.findOne(FederatedAccessAnomaly.createId(federationId, federatedPlatformId, resourceId));
        assertEquals(federationId, federatedAccessAnomalyDB.getFederationId());
        assertEquals(federatedPlatformId, federatedAccessAnomalyDB.getPlatformId());
        assertEquals(resourceId, federatedAccessAnomalyDB.getResourceId());
        assertTrue(federatedAccessAnomalyDB.getReporters().containsKey(localPlatformId));
        assertEquals(1, federatedAccessAnomalyDB.getReporters().get(localPlatformId).intValue());
    }

    @Test
    public void reportFailedFederationAuthorizationTestSuccessModifiedDBEntry() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        FederatedAccessAnomaly federatedAccessAnomalyDB = new FederatedAccessAnomaly(federationId, federatedPlatformId, resourceId, "otherIssuer");
        failedAuthenticationReportRepository.save(federatedAccessAnomalyDB);
        assertEquals(1, failedAuthenticationReportRepository.count());

        //component SH mocked to return true in SecurityRequest check
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.OK, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        //DB check if no new report added
        assertEquals(1, failedAuthenticationReportRepository.count());
        federatedAccessAnomalyDB = failedAuthenticationReportRepository.findOne(FederatedAccessAnomaly.createId(federationId, federatedPlatformId, resourceId));
        assertEquals(federationId, federatedAccessAnomalyDB.getFederationId());
        assertEquals(federatedPlatformId, federatedAccessAnomalyDB.getPlatformId());
        assertEquals(resourceId, federatedAccessAnomalyDB.getResourceId());
        assertTrue(federatedAccessAnomalyDB.getReporters().containsKey("otherIssuer"));
        assertEquals(1, federatedAccessAnomalyDB.getReporters().get("otherIssuer").intValue());
        assertTrue(federatedAccessAnomalyDB.getReporters().containsKey(localPlatformId));
        assertEquals(1, federatedAccessAnomalyDB.getReporters().get(localPlatformId).intValue());

        // again report anomaly
        assertEquals(HttpStatus.OK, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        //DB check if report modified properly
        assertEquals(1, failedAuthenticationReportRepository.count());
        federatedAccessAnomalyDB = failedAuthenticationReportRepository.findOne(FederatedAccessAnomaly.createId(federationId, federatedPlatformId, resourceId));
        assertEquals(federationId, federatedAccessAnomalyDB.getFederationId());
        assertEquals(federatedPlatformId, federatedAccessAnomalyDB.getPlatformId());
        assertEquals(resourceId, federatedAccessAnomalyDB.getResourceId());
        assertTrue(federatedAccessAnomalyDB.getReporters().containsKey(localPlatformId));
        assertEquals(2, federatedAccessAnomalyDB.getReporters().get(localPlatformId).intValue());
        assertTrue(federatedAccessAnomalyDB.getReporters().containsKey("otherIssuer"));
        assertEquals(1, federatedAccessAnomalyDB.getReporters().get("otherIssuer").intValue());
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailMalformedReportNoSecurityRequest() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(null, federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), null, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, null, localPlatformId, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, null, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, null);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), "", federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, "", localPlatformId, resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, "", resourceId);
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, "");
        assertEquals(HttpStatus.BAD_REQUEST, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));

        assertEquals(0, failedAuthenticationReportRepository.count());

    }

    @Test
    public void reportFailedFederationAuthorizationTestFailWrongFederationId() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {

        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), "wrongFederationId", federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.NOT_FOUND, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        assertEquals(0, failedAuthenticationReportRepository.count());
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailSecurityRequestNotPassing() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {
        //change mock
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(new HashSet<>());
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(new HashSet<>(), 0));
        when(mockedComponentSecurityHandler.isReceivedServiceResponseVerified(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);

        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.UNAUTHORIZED, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        assertEquals(0, failedAuthenticationReportRepository.count());
    }

    @Test(expected = ADMException.class)
    public void reportFailedFederationAuthorizationTestFailCoreAAMNotResponding() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {
        ReflectionTestUtils.setField(failedFederatedAccessReportingService, "coreInterfaceAddress", "wrong server address");
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport);
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailFederatedPlatformNotInAvailableAAMs() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {
        //change dummyCore not to return federatedPlatform in availableAAMs
        dummyCoreAAM.provideLocalPlatform = false;
        //AP is still passing due to the mock
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.NOT_FOUND, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailResourceNotAvailableInFederation() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {
        dummyPlatformAAMAndPlatformRegistry.returnResource = false;
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.NOT_FOUND, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailResourceNotAvailableInProvidedPlatform() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {
        dummyPlatformAAMAndPlatformRegistry.resourcePlatformId = "notFederatedPlatformId";
        FailedFederationAuthorizationReport failedFederationAuthorizationReport = new FailedFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), timestamp), federationId, federatedPlatformId, localPlatformId, resourceId);
        assertEquals(HttpStatus.NOT_FOUND, failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
    }

}
