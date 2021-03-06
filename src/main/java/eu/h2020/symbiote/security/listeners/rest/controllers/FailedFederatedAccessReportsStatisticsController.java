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
import io.swagger.annotations.*;
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
@Api(value = "/docs/getPlatformMisdeedsReport", description = "Exposes a service that creates reports about platform misdeeds within federations")
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
    @ApiOperation(value = "Returns information about platforms misdeeds, grouped by search origin platforms", response = OriginPlatformGroupedPlatformMisdeedsReport.class, responseContainer = "Map")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received security request was malformed"),
            @ApiResponse(code = 401, message = "Unauthorized Entry"),
            @ApiResponse(code = 500, message = "Internal Server Error")})
    public ResponseEntity<Map<String, OriginPlatformGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByPlatform(
            @RequestHeader @ApiParam(value = "Security headers", required = true) HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) @ApiParam(value = "Platform filter") String platformIdFilter,
            @RequestParam(value = "searchOriginPlatformId", required = false) @ApiParam(value = "Search Origin Platform filter") String singleSearchOriginPlatformFilter) {

        // validate the client
        HttpStatus validationHttpStatus = validateClientCredentials(httpHeaders);
        if (!validationHttpStatus.equals(HttpStatus.OK))
            return getResponseWithSecurityHeaders(null, validationHttpStatus);

        // do the magic
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> misdeedsGroupedByPlatform =
                failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByPlatform(platformIdFilter, singleSearchOriginPlatformFilter);

        return getResponseWithSecurityHeaders(misdeedsGroupedByPlatform, HttpStatus.OK);
    }

    @Override
    @ApiOperation(value = "Returns information about platforms misdeeds, grouped by federations", response = FederationGroupedPlatformMisdeedsReport.class, responseContainer = "Map")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received security request was malformed"),
            @ApiResponse(code = 401, message = "Unauthorized Entry"),
            @ApiResponse(code = 500, message = "Internal Server Error")})
    public ResponseEntity<Map<String, FederationGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByFederations(
            @RequestHeader @ApiParam(value = "Security headers", required = true) HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) @ApiParam(value = "Platform filter") String platformIdFilter,
            @RequestParam(value = "federationId", required = false) @ApiParam(value = "Federation filter") String federationIdFilter) {

        HttpStatus validationHttpStatus = validateClientCredentials(httpHeaders);
        if (!validationHttpStatus.equals(HttpStatus.OK))
            return getResponseWithSecurityHeaders(null, validationHttpStatus);

        // do the magic
        Map<String, FederationGroupedPlatformMisdeedsReport> misdeedsGroupedByFederations =
                failedFederatedAccessReportsStatisticsService.getMisdeedsGroupedByFederations(platformIdFilter, federationIdFilter);

        return getResponseWithSecurityHeaders(misdeedsGroupedByFederations, HttpStatus.OK);

    }

    private HttpStatus validateClientCredentials(@RequestHeader HttpHeaders httpHeaders) {
        try {
            SecurityRequest securityRequest;
            try {
                securityRequest = new SecurityRequest(httpHeaders.toSingleValueMap());
            } catch (InvalidArgumentsException e) {
                // cause empty map causes exception
                return HttpStatus.UNAUTHORIZED;
            }
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
        } catch (InvalidArgumentsException | MalformedJWTException e) {
            log.error("Received security request is malformed: " + e.getMessage());
            return HttpStatus.BAD_REQUEST;
        }
        return HttpStatus.OK;
    }

    private <T> ResponseEntity<T> getResponseWithSecurityHeaders(T body, HttpStatus httpStatus) {
        try {
            // prepare response
            HttpHeaders responseHttpHeaders = new HttpHeaders();
            responseHttpHeaders.add(SecurityConstants.SECURITY_RESPONSE_HEADER, componentSecurityHandlerProvider.getComponentSecurityHandler().generateServiceResponse());
            if (body == null)
                new ResponseEntity(responseHttpHeaders, httpStatus);
            return new ResponseEntity<>(body, responseHttpHeaders, httpStatus);
        } catch (SecurityHandlerException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
