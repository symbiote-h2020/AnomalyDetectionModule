package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

public interface IFeignComponentClient {

    @RequestLine("POST " + SecurityConstants.ANOMALY_DETECTION_MESSAGE)
    @Headers("Content-Type: application/json")
    Response reportAnomaly(HandleAnomalyRequest handleAnomalyRequest);

}
