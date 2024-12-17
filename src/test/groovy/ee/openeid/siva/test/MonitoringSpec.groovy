/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence")
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package ee.openeid.siva.test

import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import spock.lang.Tag

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.is

@Tag("Allure")
class MonitoringSpec extends GenericSpecification {

    @Description("Health monitor response structure")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#service-health-monitoring")
    def "Verify health response structure"() {
        expect: "health response to match structure"
        SivaRequests.getMonitoringHealth()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHealthSchema.json"))
        and: "statuses to be UP"
        SivaRequests.getMonitoringHealth()
                .then()
                .body("status", is("UP"))
                .body("components.health.status", is("UP"))
    }

    @Description("Heartbeat monitor response structure")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#simplified-health-monitoring")
    def "Verify heartbeat response structure"() {
        expect: "heartbeat response to match structure"
        SivaRequests.getMonitoringHeartbeat()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorHeartbeatSchema.json"))
        and: "status to be UP"
        SivaRequests.getMonitoringHealth()
                .then()
                .body("status", is("UP"))
    }

    @Description("Version monitor response structure")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#version-information")
    def "Verify version response structure"() {
        expect: "version response to match structure"
        SivaRequests.getMonitoringVersion()
                .then()
                .body(matchesJsonSchemaInClasspath("MonitorVersionSchema.json"))
    }
}
