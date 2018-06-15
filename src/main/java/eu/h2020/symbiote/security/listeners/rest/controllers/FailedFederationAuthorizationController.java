package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IFailedFederationAuthorization;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import io.swagger.annotations.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with reporting failed federation authentication
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see FailedFederatedAccessReportingService
 */
@Api(value = "/docs/reportFailedFederationAuthorization", description = "Exposes a service that handles reports of failed authorization within the federation")
@RestController
public class FailedFederationAuthorizationController implements IFailedFederationAuthorization {

    private static final Log log = LogFactory.getLog(FailedFederationAuthorizationController.class);

    private final FailedFederatedAccessReportingService failedFederatedAccessReportingService;
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;

    @Autowired
    public FailedFederationAuthorizationController(FailedFederatedAccessReportingService failedFederatedAccessReportingService,
                                                   ComponentSecurityHandlerProvider componentSecurityHandlerProvider) {
        this.failedFederatedAccessReportingService = failedFederatedAccessReportingService;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
    }

    @Override
    @ApiOperation(value = "Handles received reports of failed authorization within the federation", response = HttpStatus.class)
    @ApiResponses({
            @ApiResponse(code = 200, message = "Report was correctly verified and saved."),
            @ApiResponse(code = 400, message = "Received report is not correctly built."),
            @ApiResponse(code = 401, message = "Received security request doesn't provide access to reported resource."),
            @ApiResponse(code = 404, message = "Some of the reported entities are unrecognized."),
            @ApiResponse(code = 500, message = "Internal Server Error.")})
    public ResponseEntity<String> handleFailFederationAuthorizationReport(
            @RequestBody @ApiParam(name = "FailedFederationAuthorizationReport", required = true) FailedFederationAuthorizationReport failedFederationAuthorizationReport) {
        try {
            return getResponseWithSecurityHeaders(failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        } catch (Exception e) {
            log.error(e.getMessage());
            return getResponseWithSecurityHeaders(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity getResponseWithSecurityHeaders(HttpStatus httpStatus) {
        try {
            // prepare response
            HttpHeaders responseHttpHeaders = new HttpHeaders();
            responseHttpHeaders.add(SecurityConstants.SECURITY_RESPONSE_HEADER, componentSecurityHandlerProvider.getComponentSecurityHandler().generateServiceResponse());
            return new ResponseEntity(responseHttpHeaders, httpStatus);
        } catch (SecurityHandlerException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

