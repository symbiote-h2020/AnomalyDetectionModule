package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IFailedAuthorizationReport;
import eu.h2020.symbiote.security.services.FailedFederatedAccessReportingService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class FailedAuthorizationReportController implements IFailedAuthorizationReport {

    private static final Log log = LogFactory.getLog(FailedAuthorizationReportController.class);

    private final FailedFederatedAccessReportingService failedFederatedAccessReportingService;

    @Autowired
    public FailedAuthorizationReportController(FailedFederatedAccessReportingService failedFederatedAccessReportingService) {
        this.failedFederatedAccessReportingService = failedFederatedAccessReportingService;
    }

    @Override
    public ResponseEntity<String> handleFailFederationAuthorizationReport(FailFederationAuthorizationReport failFederationAuthorizationReport) {
        try {
            if (failedFederatedAccessReportingService.handleReport(failFederationAuthorizationReport)) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
