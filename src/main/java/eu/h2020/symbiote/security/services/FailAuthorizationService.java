package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.repositories.FailedAuthenticationReportRepository;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.entities.FailedAuthenticationReport;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    public FailAuthorizationService(FailedAuthenticationReportRepository failedAuthenticationReportRepository,
                                    ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                    FederationsRepository federationsRepository) {
        this.failedAuthenticationReportRepository = failedAuthenticationReportRepository;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.federationsRepository = federationsRepository;
    }

    public boolean handleReport(FailFederationAuthorizationReport failFederationAuthorizationReport) throws
            InvalidArgumentsException {
        // building SFTAP access policy
        Map<String, IAccessPolicy> admAPs = new HashMap<>();
        String singleFederatedTokenAccessPolicyId = "admPolicy";

        if (federationsRepository.exists(failFederationAuthorizationReport.getFederationId())) {
            log.debug("Federation with received status call doesn't exists.");
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
        //TODO check of resourceId - if available in this federation

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
