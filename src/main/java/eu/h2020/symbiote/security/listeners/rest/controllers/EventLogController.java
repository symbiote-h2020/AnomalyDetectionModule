package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IEventLog;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class EventLogController implements IEventLog {


    private final EventManagerService eventManagerService;

    @Autowired
    public EventLogController(EventManagerService eventManagerService) {
        this.eventManagerService = eventManagerService;
    }

    @Override
    public ResponseEntity<String> handleEventLog(EventLogRequest eventLogRequest) {
        return ResponseEntity.ok("");
    }
}
