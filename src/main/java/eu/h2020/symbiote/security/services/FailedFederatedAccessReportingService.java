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
import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.repositories.FailedAuthenticationReportRepository;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.entities.FederatedAccessAnomaly;
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
    private FailedAuthenticationReportRepository failedAuthenticationReportRepository;
    public static final String AP_NAME = "admPolicy";
    public static final String MAPPING = "/pr";
    private FederationsRepository federationsRepository;
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String coreInterfaceAddress;
    private static final Log log = LogFactory.getLog(FailedFederatedAccessReportingService.class);

    @Autowired
    public FailedFederatedAccessReportingService(FailedAuthenticationReportRepository failedAuthenticationReportRepository,
                                                 ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                                 FederationsRepository federationsRepository,
                                                 @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.failedAuthenticationReportRepository = failedAuthenticationReportRepository;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.federationsRepository = federationsRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public HttpStatus handleReport(FailFederationAuthorizationReport failFederationAuthorizationReport) throws
            InvalidArgumentsException,
            ADMException, SecurityHandlerException {
        //request check
        if (failFederationAuthorizationReport == null
                || failFederationAuthorizationReport.getSecurityRequest() == null
                || failFederationAuthorizationReport.getFederationId() == null
                || failFederationAuthorizationReport.getFederationId().isEmpty()
                || failFederationAuthorizationReport.getPlatformId() == null
                || failFederationAuthorizationReport.getPlatformId().isEmpty()
                || failFederationAuthorizationReport.getResourceId() == null
                || failFederationAuthorizationReport.getResourceId().isEmpty()
                || failFederationAuthorizationReport.getIssuersPlatform() == null
                || failFederationAuthorizationReport.getIssuersPlatform().isEmpty()
                ) {
            log.error("Received report was malformed.");
            return HttpStatus.BAD_REQUEST;
        }
        // building SFTAP access policy
        Map<String, IAccessPolicy> admAPs = new HashMap<>();

        if (!federationsRepository.exists(failFederationAuthorizationReport.getFederationId())) {
            log.error("Federation with received id doesn't exists.");
            return HttpStatus.NOT_FOUND;
        }

        Federation federation = federationsRepository.findOne(failFederationAuthorizationReport.getFederationId());

        SingleTokenAccessPolicySpecifier policySpecifier =
                new SingleTokenAccessPolicySpecifier(
                        failFederationAuthorizationReport.getFederationId(),
                        federation.getMembers().stream().map(FederationMember::getPlatformId).collect(Collectors.toSet()),
                        failFederationAuthorizationReport.getPlatformId(),
                        new HashMap<>(),
                        false);
        admAPs.put(AP_NAME, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

        //setting security request validity time to 2 minutes (from previous 1 minute)
        MutualAuthenticationHelper.SERVICE_RESPONSE_EXPIRATION_TIME = 120;

        //check if security request passes SFTAP
        if (componentSecurityHandlerProvider
                .getComponentSecurityHandler()
                .getSatisfiedPoliciesIdentifiers(admAPs, failFederationAuthorizationReport.getSecurityRequest())
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
        if (!availableAAMsCollection.getAvailableAAMs().containsKey(failFederationAuthorizationReport.getIssuersPlatform())) {
            log.error("Core AAM does not know about " + failFederationAuthorizationReport.getIssuersPlatform());
            return HttpStatus.NOT_FOUND;
        }

        AAM aam = availableAAMsCollection.getAvailableAAMs().get(failFederationAuthorizationReport.getIssuersPlatform());
        String platformRegistryAddress = aam.getAamAddress().endsWith("/aam") ? aam.getAamAddress().substring(0, aam.getAamAddress().length() - 4) + MAPPING :
                aam.getAamAddress() + MAPPING;
        //check if resource available in this federation
        IFeignPlatformRegistryClient prClient = SymbioteComponentClientFactory.createClient(
                platformRegistryAddress,
                IFeignPlatformRegistryClient.class,
                "pr",
                failFederationAuthorizationReport.getIssuersPlatform(),
                componentSecurityHandlerProvider.getComponentSecurityHandler());

        FederationSearchResult response = prClient.searchFederationAvailableResources(failFederationAuthorizationReport.getFederationId(), failFederationAuthorizationReport.getResourceId());
        if (response.getResources().isEmpty()
                || !response.getResources().get(0).getPlatformId().equals(failFederationAuthorizationReport.getPlatformId())) {
            log.error(failFederationAuthorizationReport.getResourceId() +
                    " resource is not available according to provided federation Id: " + failFederationAuthorizationReport.getFederationId() +
                    " in platform: " + failFederationAuthorizationReport.getPlatformId());
            return HttpStatus.NOT_FOUND;
        }
        //end of validation
        //create new entry or increase counter of existing one
        FederatedAccessAnomaly federatedAccessAnomalyRepo = failedAuthenticationReportRepository.findOne(
                FederatedAccessAnomaly.createId(
                        failFederationAuthorizationReport.getFederationId(),
                        failFederationAuthorizationReport.getPlatformId(),
                        failFederationAuthorizationReport.getResourceId()
                ));
        if (federatedAccessAnomalyRepo == null) {
            FederatedAccessAnomaly federatedAccessAnomaly = new FederatedAccessAnomaly(
                    failFederationAuthorizationReport.getFederationId(),
                    failFederationAuthorizationReport.getPlatformId(),
                    failFederationAuthorizationReport.getResourceId(),
                    failFederationAuthorizationReport.getIssuersPlatform());
            failedAuthenticationReportRepository.save(federatedAccessAnomaly);
            return HttpStatus.OK;
        }

        if (federatedAccessAnomalyRepo.getReporters().containsKey(failFederationAuthorizationReport.getIssuersPlatform())) {
            federatedAccessAnomalyRepo.getReporters().put(
                    failFederationAuthorizationReport.getIssuersPlatform(),
                    federatedAccessAnomalyRepo.getReporters().get(failFederationAuthorizationReport.getIssuersPlatform()) + 1);
        } else
            federatedAccessAnomalyRepo.getReporters().put(failFederationAuthorizationReport.getIssuersPlatform(), 1);
        failedAuthenticationReportRepository.save(federatedAccessAnomalyRepo);
        return HttpStatus.OK;
    }
}
