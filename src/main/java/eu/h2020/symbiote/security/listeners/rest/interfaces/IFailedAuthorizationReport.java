package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public interface IFailedAuthorizationReport {

    @PostMapping(value = SecurityConstants.LOG_FAIL_FEDERATION_AUTHORIZATION, consumes = "application/json")
    ResponseEntity handleFailFederationAuthorizationReport(@RequestBody FailedFederationAuthorizationReport failedFederationAuthorizationReport);

}
