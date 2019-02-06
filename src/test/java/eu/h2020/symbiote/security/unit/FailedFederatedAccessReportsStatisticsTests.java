package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractADMTestSuite;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import eu.h2020.symbiote.security.listeners.rest.controllers.FailedFederatedAccessReportsStatisticsController;
import eu.h2020.symbiote.security.repositories.entities.FailedFederatedAccessReport;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportsStatisticsService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpStatus;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService.AP_NAME;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class FailedFederatedAccessReportsStatisticsTests extends AbstractADMTestSuite {

    @Autowired
    FailedFederatedAccessReportsStatisticsService failedFederatedAccessReportsStatisticsService;
    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    @SpyBean
    FailedFederatedAccessReportsStatisticsController failedFederatedAccessReportsStatisticsController;

    private String searchOriginPlatformId = "testLocalPlatformId";
    private String searchOriginPlatformId2 = "testLocalPlatformId2";
    private String resourcePlatformId = "testPlatformId";
    private String resourcePlatformId2 = "testPlatformId2";
    private String federationId = "federation1";
    private String federationId2 = "federation2";
    //not in DB
    private String searchOriginPlatformId3 = "testLocalPlatformId3";
    private String resourcePlatformId3 = "testPlatformId3";
    private String federationId3 = "federation3";

    private ComponentSecurityHandler mockedComponentSecurityHandler;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        failedFederatedAccessReportsRepository.deleteAll();
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId, federationId, "res1"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId, federationId, "res2"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId, federationId, "res3"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId, federationId2, "res4"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId, federationId2, "res5"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId2, federationId, "res1"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId2, federationId, "res2"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId, searchOriginPlatformId2, federationId2, "res4"));

        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId2, searchOriginPlatformId, federationId, "res2"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId2, searchOriginPlatformId, federationId, "res3"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId2, searchOriginPlatformId, federationId2, "res5"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId2, searchOriginPlatformId2, federationId, "res2"));
        failedFederatedAccessReportsRepository.save(new FailedFederatedAccessReport(1L, resourcePlatformId2, searchOriginPlatformId2, federationId2, "res4"));

        //mocking component security handler
        mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        Set<String> set = new HashSet<>();
        set.add(AP_NAME);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(set);
        when(mockedComponentSecurityHandler.getFederationGroupedPlatformMisdeedsReports(Mockito.anyObject(), Mockito.anyObject())).thenCallRealMethod();
        when(mockedComponentSecurityHandler.getOriginPlatformGroupedPlatformMisdeedsReports(Mockito.anyObject(), Mockito.anyObject())).thenCallRealMethod();
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0dXNlcm5hbWUiLCJzdWIiOiJ0ZXN0Y2xpZW50aWQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.SGNpyl3zRA_ptRhA0lFH0o7-nhf3mpxE95ss37_jHYbCnwlRb4zDvVaYCj9DlpppU4U0y3vIPEqM44vV2UZ5Iw"));
        when(mockedComponentSecurityHandler.isReceivedServiceResponseVerified(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
        when(mockedComponentSecurityHandler.generateServiceResponse()).thenReturn("ServiceResponse");
        SecurityHandler securityHandler = Mockito.mock(SecurityHandler.class);
        AAM aam = Mockito.mock(AAM.class);
        //return server address without "/adm"
        when(aam.getAamAddress()).thenReturn(serverAddress.substring(0, serverAddress.length() - 4));
        when(securityHandler.getCoreAAMInstance()).thenReturn(aam);
        when(mockedComponentSecurityHandler.getSecurityHandler()).thenReturn(securityHandler);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
    }

    @Test
    public void getMisdeedsGroupedByPlatformNoFilters() {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(null, null);
        assertEquals(2, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(8, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId).intValue());
        assertEquals(1, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId3));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(5, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(2, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertTrue(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertEquals(1, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId3));
        assertFalse(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertFalse(response.containsKey(resourcePlatformId3));
    }

    @Test
    public void getMisdeedsGroupedByPlatformWithPlatformFilter() {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(resourcePlatformId, null);
        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(8, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId).intValue());
        assertEquals(1, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId2).get(federationId3));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(resourcePlatformId3, null);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId3));
        assertEquals(0, response.get(resourcePlatformId3).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId3).getDetailsBySearchOriginPlatform().isEmpty());
    }

    @Test
    public void getMisdeedsGroupedByPlatformWithOriginPlatformFilter() {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(null, searchOriginPlatformId);
        assertEquals(2, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(3, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(2, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertFalse(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertFalse(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertFalse(response.containsKey(resourcePlatformId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(null, searchOriginPlatformId3);
        assertEquals(2, response.size());
        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(0, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));
        assertEquals(0, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId3).size());
        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(0, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));
        assertEquals(0, response.get(resourcePlatformId2).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId3).size());
    }

    @Test
    public void getMisdeedsGroupedByPlatformWithPlatformAndOriginPlatformFilter() {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(resourcePlatformId, searchOriginPlatformId);
        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertFalse(response.containsKey(resourcePlatformId2));
        assertFalse(response.containsKey(resourcePlatformId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(resourcePlatformId, searchOriginPlatformId3);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(0, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));
        assertEquals(0, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId3).size());

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(resourcePlatformId3, searchOriginPlatformId);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId3));
        assertEquals(0, response.get(resourcePlatformId3).getTotalMisdeeds());
        assertEquals(1, response.get(resourcePlatformId3).getDetailsBySearchOriginPlatform().size());
        assertTrue(response.get(resourcePlatformId3).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(0, response.get(resourcePlatformId3).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).size());
    }

    @Test
    public void getMisdeedsGroupedByFederationNoFilters() {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(null, null);
        assertEquals(2, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(8, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId2));
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId).intValue());
        assertEquals(1, response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));

        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(5, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId));
        assertEquals(2, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertTrue(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId2));
        assertEquals(1, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId3));

        assertFalse(response.containsKey(resourcePlatformId3));
    }

    @Test
    public void getMisdeedsGroupedByFederationWithPlatformFilter() {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(resourcePlatformId, null);
        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(8, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId2));
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId).intValue());
        assertEquals(1, response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId2).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(resourcePlatformId3, null);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId3));
        assertEquals(0, response.get(resourcePlatformId3).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId3).getDetailsByFederation().isEmpty());
    }

    @Test
    public void getMisdeedsGroupedByFederationWithFederationFilter() {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(null, federationId);
        assertEquals(2, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId2));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));

        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(3, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId));
        assertEquals(2, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(1, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId2).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId2));
        assertFalse(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId2));

        assertFalse(response.containsKey(resourcePlatformId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(null, federationId3);
        assertEquals(2, response.size());
        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(0, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));
        assertEquals(0, response.get(resourcePlatformId).getDetailsByFederation().get(federationId3).size());
        assertTrue(response.containsKey(resourcePlatformId2));
        assertEquals(0, response.get(resourcePlatformId2).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId2).getDetailsByFederation().containsKey(federationId3));
        assertEquals(0, response.get(resourcePlatformId2).getDetailsByFederation().get(federationId3).size());
    }

    @Test
    public void getMisdeedsGroupedByFederationWithPlatformAndFederationFilter() {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(resourcePlatformId, federationId);
        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId2));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));

        assertFalse(response.containsKey(resourcePlatformId2));
        assertFalse(response.containsKey(resourcePlatformId3));

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(resourcePlatformId, federationId3);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(0, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));
        assertEquals(0, response.get(resourcePlatformId).getDetailsByFederation().get(federationId3).size());

        // wrong filter
        response = failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(resourcePlatformId3, federationId);
        assertEquals(1, response.size());
        assertTrue(response.containsKey(resourcePlatformId3));
        assertEquals(0, response.get(resourcePlatformId3).getTotalMisdeeds());
        assertEquals(1, response.get(resourcePlatformId3).getDetailsByFederation().size());
        assertTrue(response.get(resourcePlatformId3).getDetailsByFederation().containsKey(federationId));
        assertEquals(0, response.get(resourcePlatformId3).getDetailsByFederation().get(federationId).size());
    }

    @Test
    public void getFederationGroupedPlatformMisdeedsReportsSuccess() throws SecurityHandlerException {

        Map<String, FederationGroupedPlatformMisdeedsReport> response = componentSecurityHandlerProvider.getComponentSecurityHandler().getFederationGroupedPlatformMisdeedsReports(
                Optional.of(resourcePlatformId), Optional.of(federationId));

        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsByFederation().get(federationId).get(searchOriginPlatformId3));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId2));
        assertFalse(response.get(resourcePlatformId).getDetailsByFederation().containsKey(federationId3));

        assertFalse(response.containsKey(resourcePlatformId2));
        assertFalse(response.containsKey(resourcePlatformId3));
    }

    @Test
    public void getFederationGroupedPlatformMisdeedsReportsFailNotPassedAP() {

        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(new HashSet<>());
        try {
            componentSecurityHandlerProvider.getComponentSecurityHandler().getFederationGroupedPlatformMisdeedsReports(
                    Optional.of(resourcePlatformId), Optional.of(federationId));
            fail();
        } catch (SecurityHandlerException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void getFederationGroupedPlatformMisdeedsReportsFailEmptySecurityRequest() throws SecurityHandlerException {

        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(""));

        try {
            componentSecurityHandlerProvider.getComponentSecurityHandler().getFederationGroupedPlatformMisdeedsReports(
                    Optional.of(resourcePlatformId), Optional.of(federationId));
            fail();
        } catch (SecurityHandlerException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void getPlatformGroupedPlatformMisdeedsReportsSuccess() throws SecurityHandlerException {

        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = componentSecurityHandlerProvider.getComponentSecurityHandler().getOriginPlatformGroupedPlatformMisdeedsReports(
                Optional.of(resourcePlatformId), Optional.of(searchOriginPlatformId));

        assertEquals(1, response.size());

        assertTrue(response.containsKey(resourcePlatformId));
        assertEquals(5, response.get(resourcePlatformId).getTotalMisdeeds());
        assertTrue(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId));
        assertEquals(3, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId).intValue());
        assertEquals(2, response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId2).intValue());
        assertNull(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().get(searchOriginPlatformId).get(federationId3));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId2));
        assertFalse(response.get(resourcePlatformId).getDetailsBySearchOriginPlatform().containsKey(searchOriginPlatformId3));

        assertFalse(response.containsKey(resourcePlatformId2));
        assertFalse(response.containsKey(resourcePlatformId3));
    }

    @Test
    public void getPlatformGroupedPlatformMisdeedsReportsFailNotPassedAP() {

        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(new HashSet<>());
        try {
            componentSecurityHandlerProvider.getComponentSecurityHandler().getOriginPlatformGroupedPlatformMisdeedsReports(
                    Optional.of(resourcePlatformId), Optional.of(searchOriginPlatformId));
            fail();
        } catch (SecurityHandlerException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void getPlatformGroupedPlatformMisdeedsReportsFailEmptySecurityRequest() throws SecurityHandlerException {

        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(""));

        try {
            componentSecurityHandlerProvider.getComponentSecurityHandler().getFederationGroupedPlatformMisdeedsReports(
                    Optional.of(resourcePlatformId), Optional.of(searchOriginPlatformId));
            fail();
        } catch (SecurityHandlerException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }


}
