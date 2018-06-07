package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IFailedFederatedAccessReportsStatistics;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportsStatisticsService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with acquiring platform misdeeds reports needed for trust calculation
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see FailedFederatedAccessReportsStatisticsService
 */
@RestController
public class FailedFederatedAccessReportsStatisticsController implements IFailedFederatedAccessReportsStatistics {

    private static final Log log = LogFactory.getLog(FailedFederatedAccessReportsStatisticsController.class);
    private final FailedFederatedAccessReportsStatisticsService failedFederatedAccessReportsStatisticsService;
    private final ComponentSecurityHandlerProvider componentSecurityHandlerProvider;

    @Autowired
    public FailedFederatedAccessReportsStatisticsController(FailedFederatedAccessReportsStatisticsService failedFederatedAccessReportsStatisticsService,
                                                            ComponentSecurityHandlerProvider componentSecurityHandlerProvider) {
        this.failedFederatedAccessReportsStatisticsService = failedFederatedAccessReportsStatisticsService;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
    }

    @Override
    public ResponseEntity<Map<String, OriginPlatformGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByPlatform(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) String platformIdFilter,
            @RequestParam(value = "searchOriginPlatformId", required = false) String singleSearchOriginPlatformFilter) {
        HttpHeaders responseHttpHeaders = new HttpHeaders();
        try {
            responseHttpHeaders.add(SecurityConstants.SECURITY_RESPONSE_HEADER, componentSecurityHandlerProvider.getComponentSecurityHandler().generateServiceResponse());
        } catch (SecurityHandlerException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        try {
            SecurityRequest securityRequest = new SecurityRequest(httpHeaders.toSingleValueMap());
            HttpStatus validationHttpStatus = checkReceivedSR(securityRequest);
            if (!validationHttpStatus.equals(HttpStatus.OK))
                return new ResponseEntity<>(validationHttpStatus);
        } catch (InvalidArgumentsException | MalformedJWTException e) {
            log.error("Received security request is malformed: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(platformIdFilter, singleSearchOriginPlatformFilter), responseHttpHeaders, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<Map<String, FederationGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByFederations(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) String platformIdFilter,
            @RequestParam(value = "federationId", required = false) String federationIdFilter) {
        HttpHeaders responseHttpHeaders = new HttpHeaders();
        try {
            responseHttpHeaders.add(SecurityConstants.SECURITY_RESPONSE_HEADER, componentSecurityHandlerProvider.getComponentSecurityHandler().generateServiceResponse());
        } catch (SecurityHandlerException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        try {
            SecurityRequest securityRequest = new SecurityRequest(httpHeaders.toSingleValueMap());
            HttpStatus validationHttpStatus = checkReceivedSR(securityRequest);
            if (!validationHttpStatus.equals(HttpStatus.OK))
                return new ResponseEntity<>(validationHttpStatus);
        } catch (InvalidArgumentsException | MalformedJWTException e) {
            log.error("Received security request is malformed: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(platformIdFilter, federationIdFilter), responseHttpHeaders, HttpStatus.OK);
    }

    private HttpStatus checkReceivedSR(SecurityRequest securityRequest) throws
            MalformedJWTException,
            InvalidArgumentsException {
        if (securityRequest.getSecurityCredentials().isEmpty())
            return HttpStatus.UNAUTHORIZED;
        JWTClaims claims = JWTEngine.getClaimsFromToken(securityRequest.getSecurityCredentials().iterator().next().getToken());
        // building CHTAP access policy basing on platform found in ISS of security request token
        Map<String, IAccessPolicy> componentHomeTokenAPs = new HashMap<>();
        String componentHTPolicyId = "admAccessPolicy";
        SingleTokenAccessPolicySpecifier policySpecifier =
                new SingleTokenAccessPolicySpecifier("tm", claims.getIss());
        componentHomeTokenAPs.put(componentHTPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

        if (componentSecurityHandlerProvider
                .getComponentSecurityHandler()
                .getSatisfiedPoliciesIdentifiers(componentHomeTokenAPs, securityRequest)
                .size() != 1) {
            log.error("Received security request is not passing ADM Access Policy.");
            return HttpStatus.UNAUTHORIZED;
        }
        return HttpStatus.OK;
    }

}
