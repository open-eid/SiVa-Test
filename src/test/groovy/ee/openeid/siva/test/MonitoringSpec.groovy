package ee.openeid.siva.test

import ee.openeid.siva.test.request.SivaRequests
import org.hamcrest.Matchers
import org.junit.jupiter.api.Tag

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
@Tag("Allure")
class MonitoringSpec extends GenericSpecification {
    /**
     * TestCaseID: WebApp-Monitoring-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#service-health-monitoring
     *
     * Title: Health monitor response structure
     *
     * Expected Result: response matches the expected structure of JSON
     *
     * File: not relevant
     */
    def "requestingWebAppMonitoringHealthStatusShouldReturnProperStructure"() {
        expect:
        SivaRequests.getMonitoringHealth()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHealthSchema.json"))
                .body("status", Matchers.is("UP"))
                .body("components.health.status", Matchers.is("UP"))
    }

    /**
     * TestCaseID: WebApp-Monitoring-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#simplified-health-monitoring
     *
     * Title: Heartbeat monitor response structure
     *
     * Expected Result: response matches the expected structure of JSON
     *
     * File: not relevant
     */
    def "requestingWebAppMonitoringHeartbeatStatusShouldReturnProperStructure"() {
        expect:
        SivaRequests.getMonitoringHeartbeat()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHeartbeatSchema.json"))
                .body("status", Matchers.is("UP"))
    }

    /**
     * TestCaseID: WebApp-Monitoring-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#version-information
     *
     * Title: Version monitor response structure
     *
     * Expected Result: response matches the expected structure of JSON
     *
     * File: not relevant
     */
    def "requestingWebAppMonitoringVersionInfoShouldReturnProperStructure"() {
        expect:
        SivaRequests.getMonitoringVersion()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorVersionSchema.json"))
    }
}
