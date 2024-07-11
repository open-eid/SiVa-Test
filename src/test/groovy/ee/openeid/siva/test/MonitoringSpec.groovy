package ee.openeid.siva.test

import ee.openeid.siva.test.allure.SivaRequirement
import ee.openeid.siva.test.request.SivaRequests
import org.hamcrest.Matchers
import spock.lang.Tag

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath

@Tag("Allure")
class MonitoringSpec extends GenericSpecification {

    @SivaRequirement("interfaces/#service-health-monitoring")
    def "Verify health response structure"() {
        expect: "health response to match structure"
        SivaRequests.getMonitoringHealth()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHealthSchema.json"))
        and: "statuses to be UP"
        SivaRequests.getMonitoringHealth()
                .then()
                .body("status", Matchers.is("UP"))
                .body("components.health.status", Matchers.is("UP"))
    }

    @SivaRequirement("interfaces/#simplified-health-monitoring")
    def "Verify heartbeat response structure"() {
        expect: "heartbeat response to match structure"
        SivaRequests.getMonitoringHeartbeat()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHeartbeatSchema.json"))
        and: "status to be UP"
        SivaRequests.getMonitoringHealth()
                .then()
                .body("status", Matchers.is("UP"))
    }

    @SivaRequirement("interfaces/#version-information")
    def "Verify version response structure"() {
        expect: "version response to match structure"
        SivaRequests.getMonitoringVersion()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorVersionSchema.json"))
    }
}
