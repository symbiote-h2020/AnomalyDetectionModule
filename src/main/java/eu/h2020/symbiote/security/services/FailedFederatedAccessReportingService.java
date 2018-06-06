package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.client.SymbioteComponentClientFactory;
import eu.h2020.symbiote.cloud.model.internal.FederationSearchResult;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.interfaces.IFeignPlatformRegistryClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.repositories.FailedFederatedAccessReportsRepository;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.entities.FailedFederatedAccessReport;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FailedFederatedAccessReportingService {
    private FailedFederatedAccessReportsRepository failedFederatedAccessReportsRepository;
    public static final String AP_NAME = "admPolicy";
    public static final String MAPPING = "/pr";
    private FederationsRepository federationsRepository;
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String coreInterfaceAddress;
    private static final Log log = LogFactory.getLog(FailedFederatedAccessReportingService.class);

    @Autowired
    public FailedFederatedAccessReportingService(FailedFederatedAccessReportsRepository failedFederatedAccessReportsRepository,
                                                 ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                                 FederationsRepository federationsRepository,
                                                 @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.failedFederatedAccessReportsRepository = failedFederatedAccessReportsRepository;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.federationsRepository = federationsRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public HttpStatus handleReport(FailedFederationAuthorizationReport failedFederationAuthorizationReport) throws
            InvalidArgumentsException,
            ADMException, SecurityHandlerException {
        //request check
        if (failedFederationAuthorizationReport == null
                || failedFederationAuthorizationReport.getSecurityRequest() == null
                || failedFederationAuthorizationReport.getFederationId() == null
                || failedFederationAuthorizationReport.getFederationId().isEmpty()
                || failedFederationAuthorizationReport.getResourcePlatformId() == null
                || failedFederationAuthorizationReport.getResourcePlatformId().isEmpty()
                || failedFederationAuthorizationReport.getResourceId() == null
                || failedFederationAuthorizationReport.getResourceId().isEmpty()
                || failedFederationAuthorizationReport.getSearchOriginPlatformId() == null
                || failedFederationAuthorizationReport.getSearchOriginPlatformId().isEmpty()
                ) {
            log.error("Received report was malformed.");
            return HttpStatus.BAD_REQUEST;
        }
        // building SFTAP access policy
        Map<String, IAccessPolicy> admAPs = new HashMap<>();

        if (!federationsRepository.exists(failedFederationAuthorizationReport.getFederationId())) {
            log.error("Federation with received id doesn't exists.");
            return HttpStatus.NOT_FOUND;
        }

        Federation federation = federationsRepository.findOne(failedFederationAuthorizationReport.getFederationId());

        SingleTokenAccessPolicySpecifier policySpecifier =
                new SingleTokenAccessPolicySpecifier(
                        failedFederationAuthorizationReport.getFederationId(),
                        federation.getMembers().stream().map(FederationMember::getPlatformId).collect(Collectors.toSet()),
                        failedFederationAuthorizationReport.getResourcePlatformId(),
                        new HashMap<>(),
                        false);
        admAPs.put(AP_NAME, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

        //setting security request validity time to 2 minutes (from previous 1 minute)
        MutualAuthenticationHelper.SERVICE_RESPONSE_EXPIRATION_TIME = 120;

        //check if security request passes SFTAP
        if (componentSecurityHandlerProvider
                .getComponentSecurityHandler()
                .getSatisfiedPoliciesIdentifiers(admAPs, failedFederationAuthorizationReport.getSecurityRequest())
                .size() != 1) {
            log.error("SecurityRequest did not pass the SFT access policy.");
            return HttpStatus.UNAUTHORIZED;
        }

        //get the platform address
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        AvailableAAMsCollection availableAAMsCollection;
        try {
            availableAAMsCollection = aamClient.getAvailableAAMs();
        } catch (AAMException e) {
            throw new ADMException("Core AAM is not responding.");
        }
        //check if platform is registered in core
        if (!availableAAMsCollection.getAvailableAAMs().containsKey(failedFederationAuthorizationReport.getSearchOriginPlatformId())) {
            log.error("Core AAM does not know about " + failedFederationAuthorizationReport.getSearchOriginPlatformId());
            return HttpStatus.NOT_FOUND;
        }

        AAM aam = availableAAMsCollection.getAvailableAAMs().get(failedFederationAuthorizationReport.getSearchOriginPlatformId());
        String platformRegistryAddress = aam.getAamAddress().endsWith("/aam") ? aam.getAamAddress().substring(0, aam.getAamAddress().length() - 4) + MAPPING :
                aam.getAamAddress() + MAPPING;
        //check if resource available in this federation
        IFeignPlatformRegistryClient prClient = SymbioteComponentClientFactory.createClient(
                platformRegistryAddress,
                IFeignPlatformRegistryClient.class,
                "pr",
                failedFederationAuthorizationReport.getSearchOriginPlatformId(),
                componentSecurityHandlerProvider.getComponentSecurityHandler());

        FederationSearchResult response = prClient.searchFederationAvailableResources(failedFederationAuthorizationReport.getFederationId(), failedFederationAuthorizationReport.getResourceId());
        if (response.getResources().isEmpty()
                || !response.getResources().get(0).getPlatformId().equals(failedFederationAuthorizationReport.getResourcePlatformId())) {
            log.error(failedFederationAuthorizationReport.getResourceId() +
                    " resource is not available according to provided federation Id: " + failedFederationAuthorizationReport.getFederationId() +
                    " in platform: " + failedFederationAuthorizationReport.getResourcePlatformId());
            return HttpStatus.NOT_FOUND;
        }
        //end of validation
        //put report to DB
        FailedFederatedAccessReport failedFederatedAccessReport = new FailedFederatedAccessReport(
                failedFederationAuthorizationReport.getSecurityRequest().getTimestamp(),
                failedFederationAuthorizationReport.getResourcePlatformId(),
                failedFederationAuthorizationReport.getSearchOriginPlatformId(),
                failedFederationAuthorizationReport.getFederationId(),
                failedFederationAuthorizationReport.getResourceId()
        );
        failedFederatedAccessReportsRepository.save(failedFederatedAccessReport);
        return HttpStatus.OK;
    }
}
