package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.cloud.model.internal.FederationSearchResult;
import feign.Param;
import feign.RequestLine;

/**
 * Feign Client responsible for communication with Platform Registryparam
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignPlatformRegistryClient {

    @RequestLine("GET /list_resources_in_predicate?federationId={federationId}&id={id}")
    FederationSearchResult searchFederationAvailableResources(@Param("federationId") String federationId, @Param("id") String resourceId);
}