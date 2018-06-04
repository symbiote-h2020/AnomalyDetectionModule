package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.cloud.model.internal.FederationSearchResult;
import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignPlatformRegistryClient;
import eu.h2020.symbiote.security.communication.interfaces.IPlatformRegistryClient;
import feign.Feign;
import feign.Logger;
import feign.Logger.Level;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Collections;

/**
 * Crude RMI-like client's implementation to the Platform Registry module that communicates with it over REST.
 *
 * @author Jakub Toczek (PSNC)
 */
public class PlatformRegistryClient implements IPlatformRegistryClient {
    public static final String MAPPING = "/pr";
    private static final Log logger = LogFactory.getLog(PlatformRegistryClient.class);
    private String serverAddress;
    private IFeignPlatformRegistryClient feignClient;

    /**
     * @param serverAddress of the Platform Registry server the client wants to interact with.
     */
    public PlatformRegistryClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the Platform Registry server the client wants to interact with.
     * @param logger        feign logger
     */
    public PlatformRegistryClient(String serverAddress, Logger logger) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient(logger);
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignPlatformRegistryClient getJsonClient(Logger logger) {
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .logger(logger)
                .logLevel(Level.FULL)
                .target(IFeignPlatformRegistryClient.class, serverAddress);
    }


    @Override
    public boolean isResourceAvailable(String federationId, String resourceId) throws
            ADMException {

        ResponseEntity responseEntity = feignClient.isResourceAvailable(Collections.singletonList(federationId), Collections.singletonList(resourceId));
        if (!responseEntity.getStatusCode().equals(HttpStatus.OK)) {
            throw new ADMException("Platform Registry is not available.");
        }
        FederationSearchResult searchResult = (FederationSearchResult) responseEntity.getBody();
        return searchResult.getResources().size() == 1;
    }
}
