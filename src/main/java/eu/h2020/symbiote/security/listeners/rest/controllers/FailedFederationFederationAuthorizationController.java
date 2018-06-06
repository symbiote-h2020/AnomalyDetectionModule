package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IFailedFederationAuthorization;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class FailedFederationFederationAuthorizationController implements IFailedFederationAuthorization {

    private static final Log log = LogFactory.getLog(FailedFederationFederationAuthorizationController.class);

    private final FailedFederatedAccessReportingService failedFederatedAccessReportingService;

    @Autowired
    public FailedFederationFederationAuthorizationController(FailedFederatedAccessReportingService failedFederatedAccessReportingService) {
        this.failedFederatedAccessReportingService = failedFederatedAccessReportingService;
    }

    @Override
    public ResponseEntity<String> handleFailFederationAuthorizationReport(FailedFederationAuthorizationReport failedFederationAuthorizationReport) {
        try {
            return new ResponseEntity<>(failedFederatedAccessReportingService.handleReport(failedFederationAuthorizationReport));
        } catch (Exception e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
