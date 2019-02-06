package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/**
 *
 * @author Piotr Jakubowski (PSNC)
 */
public interface IFeignComponentClient {

    @RequestLine("POST " + SecurityConstants.ANOMALY_DETECTION_MESSAGE)
    @Headers("Content-Type: application/json")
    Response reportAnomaly(HandleAnomalyRequest handleAnomalyRequest);

    @RequestLine("POST " + SecurityConstants.LOW_PLATFORM_REPUTATION)
    @Headers("Content-Type: application/json")
    Response handleLowPlatformReputationRequest(String platformId);

    @RequestLine("POST " + SecurityConstants.ANOMALY_SOURCE_AAM_NOTIFICATION)
    @Headers("Content-Type: application/json")
    Response notifySourceAAM(HandleAnomalyRequest handleAnomalyRequest);
}
