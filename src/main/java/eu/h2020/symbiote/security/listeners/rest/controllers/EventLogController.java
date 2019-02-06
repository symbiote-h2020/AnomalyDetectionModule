package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IEventLog;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class EventLogController implements IEventLog {

    private static final Log log = LogFactory.getLog(EventLogController.class);

    private final EventManagerService eventManagerService;

    @Autowired
    public EventLogController(EventManagerService eventManagerService) {
        this.eventManagerService = eventManagerService;
    }

    @Override
    public ResponseEntity<String> handleEventLog(EventLogRequest eventLogRequest) {
        try {
            return eventManagerService.handleEvent(eventLogRequest);
        } catch (WrongCredentialsException | InvalidArgumentsException | AssertionError e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
