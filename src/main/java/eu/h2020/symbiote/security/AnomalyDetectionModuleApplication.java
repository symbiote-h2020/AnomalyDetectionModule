package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = "eu.h2020.symbiote.security")
public class AnomalyDetectionModuleApplication {

    public static void main(String[] args) {
        ECDSAHelper.enableECDSAProvider();
        WaitForPort.waitForServices(WaitForPort.findProperty("SPRING_BOOT_WAIT_FOR_SERVICES"));
        SpringApplication.run(AnomalyDetectionModuleApplication.class, args);
    }
}
