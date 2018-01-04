package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;

public interface IComponentClient {

    /**
     * Allow to report detected anomaly.
     *
     * @param handleAnomalyRequest required to report detected anomaly.
     * @return true/false depending on anomaly handling status
     */
    String reportAnomaly(HandleAnomalyRequest handleAnomalyRequest) throws InvalidArgumentsException, WrongCredentialsException;

    /**
     * Allow to low platform reputation.
     *
     * @param platformId platform with low reputation.
     * @return true/false depending on reporting success
     */
    String reportLowPlatformReputation(String platformId);

    /**
     * Allow to notify source aam about suspicious actor.
     *
     * @param handleAnomalyRequest required to report detected anomaly.
     * @return true/false depending on notifying status
     */
    String notifySourceAAM(HandleAnomalyRequest handleAnomalyRequest) throws InvalidArgumentsException, WrongCredentialsException;


}
