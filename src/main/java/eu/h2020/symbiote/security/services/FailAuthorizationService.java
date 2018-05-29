package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.repositories.FailedAuthenticationReportRepository;
import eu.h2020.symbiote.security.repositories.entities.FailedAuthenticationReport;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class FailAuthorizationService {
    private FailedAuthenticationReportRepository failedAuthenticationReportRepository;

    @Autowired
    public FailAuthorizationService(FailedAuthenticationReportRepository failedAuthenticationReportRepository) {
        this.failedAuthenticationReportRepository = failedAuthenticationReportRepository;
    }

    public boolean handleReport(FailFederationAuthorizationReport failFederationAuthorizationReport) {
        //TODO check of SecurityRequest
        ComponentSecurityHandler componentSecurityHandler;
        //TODO check of resourceId - if available in this federation
        //TODO saving report intoDB
        failFederationAuthorizationReport.getSecurityRequest();
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
