package eu.h2020.symbiote.security.communication.interfaces;

import feign.RequestLine;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * Feign Client responsible for communication with Platform Registry
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignPlatformRegistryClient {

    @RequestLine("GET " + "/list_resources_in_predicate/")
    ResponseEntity isResourceAvailable(@RequestParam("federationId") List<String> federationIds, @RequestParam("id") List<String> resourceIds);
}