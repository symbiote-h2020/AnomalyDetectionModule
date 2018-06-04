package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.PlatformRegistryClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.repositories.FailedAuthenticationReportRepository;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.entities.FailedAuthenticationReport;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FailAuthorizationService {
    private FailedAuthenticationReportRepository failedAuthenticationReportRepository;
    private static final Log log = LogFactory.getLog(FailAuthorizationService.class);
    private FederationsRepository federationsRepository;
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String coreInterfaceAddress;

    @Autowired
    public FailAuthorizationService(FailedAuthenticationReportRepository failedAuthenticationReportRepository,
                                    ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                    FederationsRepository federationsRepository,
                                    @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.failedAuthenticationReportRepository = failedAuthenticationReportRepository;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.federationsRepository = federationsRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public boolean handleReport(FailFederationAuthorizationReport failFederationAuthorizationReport) throws
            InvalidArgumentsException, ADMException {
        //request check
        if (failFederationAuthorizationReport == null
                || failFederationAuthorizationReport.getSecurityRequest() == null
                || failFederationAuthorizationReport.getFederationId() == null
                || failFederationAuthorizationReport.getFederationId().isEmpty()
                || failFederationAuthorizationReport.getPlatformId() == null
                || failFederationAuthorizationReport.getPlatformId().isEmpty()
                || failFederationAuthorizationReport.getResourceId() == null
                || failFederationAuthorizationReport.getResourceId().isEmpty()
                ) {
            log.error("Received report was malformed.");
            return false;
        }
        // building SFTAP access policy
        Map<String, IAccessPolicy> admAPs = new HashMap<>();
        String singleFederatedTokenAccessPolicyId = "admPolicy";

        if (federationsRepository.exists(failFederationAuthorizationReport.getFederationId())) {
            log.debug("Federation with received id doesn't exists.");
            return false;
        }

        Federation federation = federationsRepository.findOne(failFederationAuthorizationReport.getFederationId());

        SingleTokenAccessPolicySpecifier policySpecifier =
                new SingleTokenAccessPolicySpecifier(
                        failFederationAuthorizationReport.getFederationId(),
                        federation.getMembers().stream().map(FederationMember::getPlatformId).collect(Collectors.toSet()),
                        failFederationAuthorizationReport.getPlatformId(),
                        new HashMap<>(),
                        false);
        admAPs.put(singleFederatedTokenAccessPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

        //setting security request validity time to 2 minutes (from previous 1 minute)
        MutualAuthenticationHelper.SERVICE_RESPONSE_EXPIRATION_TIME = 120;

        //check if security request passes SFTAP
        if (componentSecurityHandlerProvider
                .getComponentSecurityHandler()
                .getSatisfiedPoliciesIdentifiers(admAPs, failFederationAuthorizationReport.getSecurityRequest())
                .size() != 1) {
            log.debug("SecurityRequest did not pass the SFT access policy.");
            return false;
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
        if (!availableAAMsCollection.getAvailableAAMs().containsKey(failFederationAuthorizationReport.getPlatformId()))
            throw new ADMException("Core AAM does not know about " + failFederationAuthorizationReport.getPlatformId());

        AAM aam = availableAAMsCollection.getAvailableAAMs().get(failFederationAuthorizationReport.getPlatformId());
        String platformRegistryAddress = aam.getAamAddress().endsWith("/aam") ? aam.getAamAddress().substring(0, aam.getAamAddress().length() - 4) + PlatformRegistryClient.MAPPING :
                aam.getAamAddress() + PlatformRegistryClient.MAPPING;
        //check if resource available in this federation
        PlatformRegistryClient platformRegistryClient = new PlatformRegistryClient(platformRegistryAddress);
        if (!platformRegistryClient.isResourceAvailable(failFederationAuthorizationReport.getFederationId(), failFederationAuthorizationReport.getResourceId())) {
            log.error(failFederationAuthorizationReport.getResourceId() + " resource is not available according to provided federation Id: " + failFederationAuthorizationReport.getFederationId());
            return false;
        }
        //end of validation
        //create new entry or increase counter of existing one
        FailedAuthenticationReport failedAuthenticationReportRepo = failedAuthenticationReportRepository.findOne(
                FailedAuthenticationReport.createId(
                        failFederationAuthorizationReport.getFederationId(),
                        failFederationAuthorizationReport.getPlatformId(),
                        failFederationAuthorizationReport.getResourceId()
                ));
        if (failedAuthenticationReportRepo == null) {
            FailedAuthenticationReport failedAuthenticationReport = new FailedAuthenticationReport(
                    failFederationAuthorizationReport.getFederationId(),
                    failFederationAuthorizationReport.getPlatformId(),
                    failFederationAuthorizationReport.getResourceId());
            failedAuthenticationReportRepository.save(failedAuthenticationReport);
            return true;
        }
        failedAuthenticationReportRepo.increaseCounter();
        failedAuthenticationReportRepository.save(failedAuthenticationReportRepo);
        return true;
    }
}
