/*
 * Copyright 2024 - 2026 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test.generalEndpoints

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is

@Epic("General endpoints")
@Feature("Monitoring endpoint validation")
class MonitoringSpec extends GenericSpecification {

    @Story("Health response validation")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#service-health-monitoring")
    def "Health response structure matches schema and status is UP"() {
        expect: "valid response is returned"
        SivaRequests.getMonitoringHealth().then()
                .body(matchesJsonSchemaInClasspath("schemas/MonitorHealthSchema.json"))
                .body("status", is("UP"))
                .body("components.health.status", is("UP"))
    }

    @Story("Heartbeat response validation")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#simplified-health-monitoring")
    def "Heartbeat response structure matches schema and status is UP"() {
        expect: "valid response is returned"
        SivaRequests.getMonitoringHeartbeat().then()
                .body(matchesJsonSchemaInClasspath("schemas/MonitorHeartbeatSchema.json"))
                .body("status", is("UP"))
    }

    @Story("Version response validation")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#version-information")
    def "Version response structure matches schema"() {
        expect: "valid response is returned"
        SivaRequests.getMonitoringVersion()
                .then()
                .body(matchesJsonSchemaInClasspath("schemas/MonitorVersionSchema.json"))
    }

    @Story("Prometheus monitoring")
    def "Verify prometheus valid response"() {
        expect: "prometheus response returns valid response"
        SivaRequests.getMonitoringPrometheus().then()
                .body(containsString("# HELP"))
                .body(containsString("jvm_memory_used_bytes"))
                .body(containsString("http_server_requests_seconds"))
                .body(containsString("tomcat_"))
    }

    @Story("Readiness/liveness response validation")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#simplified-health-monitoring")
    def "Monitoring #endpoint response structure matches schema and status is UP"() {
        expect: "valid response is returned"
        SivaRequests.get("/monitoring/health/" + endpoint).then()
                .statusCode(HttpStatus.SC_OK)
                .body(matchesJsonSchemaInClasspath("schemas/MonitorHeartbeatSchema.json"))
                .body("status", is("UP"))

        where:
        endpoint << ["readiness", "liveness"]
    }
}
