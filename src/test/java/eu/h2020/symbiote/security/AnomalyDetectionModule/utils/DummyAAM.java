package eu.h2020.symbiote.security.AnomalyDetectionModule.utils;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
public class DummyAAM {
    private static final Log log = LogFactory.getLog(DummyAAM.class);
    private static final String PATH = "/test/paam";

    public DummyAAM() {
    }


    @PostMapping(path = PATH + SecurityConstants.ANOMALY_DETECTION_MESSAGE, produces = "application/json")
    public ResponseEntity<String> acceptAnomaly(@RequestBody HandleAnomalyRequest handleAnomalyRequest)
    {
        return new ResponseEntity<>("true", HttpStatus.OK);
    }

}

