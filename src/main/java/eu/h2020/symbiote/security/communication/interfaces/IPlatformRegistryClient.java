package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;

/**
 * Crude RMI-like client's interface to the Platform Registry module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IPlatformRegistryClient {

    /**
     * @param federationId federation Id within resource should be available
     * @param resourceId   resource Id
     * @return true if resource is available
     */
    boolean isResourceAvailable(String federationId, String resourceId) throws ADMException;
}
