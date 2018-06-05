package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractADMTestSuite;
import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.entities.FailedAuthenticationReport;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService.AP_NAME;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.when;

public class FailedAuthorizationUnitTests extends AbstractADMTestSuite {

    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String issuer = "testIssuerPlatformId";
    private String platformId = "testPlatformId";
    private String federationId = "testFederationId";
    private String resourceId = "testResourceId";
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
        federationMember.setPlatformId(platformId);
        federationMembers.add(federationMember);
        FederationMember federationMember2 = new FederationMember();
        federationMember2.setPlatformId(issuer);
        federationMembers.add(federationMember2);
        federation.setMembers(federationMembers);
        federation.setId(federationId);
        federationsRepository.save(federation);
    }

    @Test
    public void reportFailedFederationAuthorizationTestSuccessNewDBEntry() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        //component SH mocked to return true in SecurityRequest check
        FailFederationAuthorizationReport failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, issuer, resourceId);
        assertTrue(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));
        //DB check if new report added
        assertEquals(1, failedAuthenticationReportRepository.count());
        FailedAuthenticationReport failedAuthenticationReportDB = failedAuthenticationReportRepository.findOne(FailedAuthenticationReport.createId(federationId, platformId, resourceId));
        assertEquals(federationId, failedAuthenticationReportDB.getFederationId());
        assertEquals(platformId, failedAuthenticationReportDB.getPlatformId());
        assertEquals(resourceId, failedAuthenticationReportDB.getResourceId());
        assertTrue(failedAuthenticationReportDB.getReporters().containsKey(issuer));
        assertEquals(1, failedAuthenticationReportDB.getReporters().get(issuer).intValue());
    }

    @Test
    public void reportFailedFederationAuthorizationTestSuccessModifiedDBEntry() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        FailedAuthenticationReport failedAuthenticationReportDB = new FailedAuthenticationReport(federationId, platformId, resourceId, "otherIssuer");
        failedAuthenticationReportRepository.save(failedAuthenticationReportDB);
        assertEquals(1, failedAuthenticationReportRepository.count());

        //component SH mocked to return true in SecurityRequest check
        FailFederationAuthorizationReport failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, issuer, resourceId);
        assertTrue(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));
        //DB check if no new report added
        assertEquals(1, failedAuthenticationReportRepository.count());
        failedAuthenticationReportDB = failedAuthenticationReportRepository.findOne(FailedAuthenticationReport.createId(federationId, platformId, resourceId));
        assertEquals(federationId, failedAuthenticationReportDB.getFederationId());
        assertEquals(platformId, failedAuthenticationReportDB.getPlatformId());
        assertEquals(resourceId, failedAuthenticationReportDB.getResourceId());
        assertTrue(failedAuthenticationReportDB.getReporters().containsKey("otherIssuer"));
        assertEquals(1, failedAuthenticationReportDB.getReporters().get("otherIssuer").intValue());
        assertTrue(failedAuthenticationReportDB.getReporters().containsKey(issuer));
        assertEquals(1, failedAuthenticationReportDB.getReporters().get(issuer).intValue());

        // again report anomaly
        assertTrue(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));
        //DB check if report modified properly
        assertEquals(1, failedAuthenticationReportRepository.count());
        failedAuthenticationReportDB = failedAuthenticationReportRepository.findOne(FailedAuthenticationReport.createId(federationId, platformId, resourceId));
        assertEquals(federationId, failedAuthenticationReportDB.getFederationId());
        assertEquals(platformId, failedAuthenticationReportDB.getPlatformId());
        assertEquals(resourceId, failedAuthenticationReportDB.getResourceId());
        assertTrue(failedAuthenticationReportDB.getReporters().containsKey(issuer));
        assertEquals(2, failedAuthenticationReportDB.getReporters().get(issuer).intValue());
        assertTrue(failedAuthenticationReportDB.getReporters().containsKey("otherIssuer"));
        assertEquals(1, failedAuthenticationReportDB.getReporters().get("otherIssuer").intValue());
    }

    @Test
    public void reportFailedFederationAuthorizationTestFailMalformedReportNoSecurityRequest() throws
            ADMException,
            InvalidArgumentsException,
            SecurityHandlerException {

        FailFederationAuthorizationReport failFederationAuthorizationReport = new FailFederationAuthorizationReport(null, federationId, platformId, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), null, platformId, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, null, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, null, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, issuer, null);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), "", platformId, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, "", issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, "", resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, issuer, "");
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));

        assertEquals(0, failedAuthenticationReportRepository.count());

    }

    @Test
    public void reportFailedFederationAuthorizationTestFailWrongFederationId() throws
            InvalidArgumentsException,
            ADMException,
            SecurityHandlerException {

        FailFederationAuthorizationReport failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), "wrongFederationId", platformId, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));
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

        FailFederationAuthorizationReport failFederationAuthorizationReport = new FailFederationAuthorizationReport(new SecurityRequest(new HashSet<>(), 100l), federationId, platformId, issuer, resourceId);
        assertFalse(failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport));
        assertEquals(0, failedAuthenticationReportRepository.count());
    }

}
