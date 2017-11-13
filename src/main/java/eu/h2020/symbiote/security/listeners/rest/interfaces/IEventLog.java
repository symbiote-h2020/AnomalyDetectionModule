package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public interface IEventLog {

    @PostMapping(value = SecurityConstants.LOG_ANOMALY_EVENT, consumes = "application/json")
    ResponseEntity<String> handleEventLog(@RequestBody EventLogRequest eventLogRequest);

}
