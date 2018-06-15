package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

/**
 * Exposes a service that allows Trust Manager to acquire platforms misdeeds reports.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@RequestMapping(SecurityConstants.ADM_GET_FEDERATED_MISDEEDS)
public interface IFailedFederatedAccessReportsStatistics {
    /**
     * Acquire platform misdeeds reports needed for trust calculation, grouped by search origin platforms
     *
     * @param httpHeaders                      security request headers
     * @param platformIdFilter                 optional platform filter
     * @param singleSearchOriginPlatformFilter optional search origin platform filter
     * @return map of platforms misdeeds reports
     */
    @GetMapping(value = "/bySearchOriginPlatform")
    ResponseEntity<Map<String, OriginPlatformGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByPlatform(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) String platformIdFilter,
            @RequestParam(value = "searchOriginPlatformId", required = false) String singleSearchOriginPlatformFilter);

    /**
     * Acquire platform misdeeds reports needed for trust calculation, grouped by federations
     *
     * @param httpHeaders        security request headers
     * @param platformIdFilter   optional platform filter
     * @param federationIdFilter optional federation filter
     * @return map of platforms misdeeds reports
     */
    @GetMapping(value = "/byFederation")
    ResponseEntity<Map<String, FederationGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByFederations(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestParam(value = "platformId", required = false) String platformIdFilter,
            @RequestParam(value = "federationId", required = false) String federationIdFilter);
}
