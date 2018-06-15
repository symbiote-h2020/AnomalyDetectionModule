package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows clients to report failed federation authentication.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFailedFederationAuthorization {

    /**
     * Report failed federation authentication
     *
     * @param failedFederationAuthorizationReport containing essential information about the anomaly
     * @return HttpStatus of the operation
     */
    @PostMapping(value = SecurityConstants.ADM_LOG_FAILED_FEDERATION_AUTHORIZATION, consumes = "application/json")
    ResponseEntity handleFailFederationAuthorizationReport(@RequestBody FailedFederationAuthorizationReport failedFederationAuthorizationReport);

}
