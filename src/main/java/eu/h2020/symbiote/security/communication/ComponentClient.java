package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignComponentClient;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import feign.Feign;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

public class ComponentClient implements IComponentClient {

    private String serverAddress;
    private IFeignComponentClient feignClient;

    /**
     * @param serverAddress of the server the client wants to interact with.
     */
    public ComponentClient(String serverAddress) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient();
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignComponentClient getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(IFeignComponentClient.class, serverAddress);
    }

    /**
     * Allow to report detected anomaly.
     *
     * @param handleAnomalyRequest required to report detected anomaly.
     * @return true/false depending on anomaly handling status
     */
    @Override
    public String reportAnomaly(HandleAnomalyRequest handleAnomalyRequest) throws InvalidArgumentsException, WrongCredentialsException {
        Response response = feignClient.reportAnomaly(handleAnomalyRequest);
        return response.body().toString();
    }

    /**
     * Allow to low platform reputation.
     *
     * @param platformId platform with low reputation.
     * @return true/false depending on reporting success
     */
    @Override
    public String reportLowPlatformReputation(String platformId) {
        Response response = feignClient.handleLowPlatformReputationRequest(platformId);
        return response.body().toString();
    }

    /**
     * Allow to notify source aam about suspicious actor.
     *
     * @param handleAnomalyRequest required to report detected anomaly.
     * @return true/false depending on notifying status
     */
    @Override
    public String notifySourceAAM(HandleAnomalyRequest handleAnomalyRequest) throws InvalidArgumentsException, WrongCredentialsException {
        Response response = feignClient.notifySourceAAM(handleAnomalyRequest);
        return response.body().toString();
    }

}
