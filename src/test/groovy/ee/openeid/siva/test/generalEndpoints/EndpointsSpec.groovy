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
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given

@Epic("General endpoints")
@Feature("General endpoints checks")
class EndpointsSpec extends GenericSpecification {

    @Story("Not allowed endpoints return error")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces")
    def "Soap #endpoint endpoint deprecated"() {
        given: "deprecated soap endpoint URL is used"
        String sivaServiceUrl = "${conf.sivaProtocol()}://${conf.sivaHostname()}:${conf.sivaPort()}${conf.sivaContextPath()}"

        expect: "not found error to be returned"
        given()
                .contentType("text/xml;charset=UTF-8")
                .body("<test></test>")
                .when()
                .post(sivaServiceUrl + "/soap/" + endpoint)
                .then()
                .statusCode(HttpStatus.SC_NOT_FOUND)

        where:
        endpoint                       | _
        "validationWebService"         | _
        "hashcodeValidationWebService" | _
        "dataFilesWebService"          | _
    }

    @Story("Not allowed endpoints return error")
    def "When #description is used then error is returned"() {
        expect: "non-existing endpoint returns correct error"
        SivaRequests.get(endpoint).then().statusCode(HttpStatus.SC_NOT_FOUND)

        where:
        description                        | endpoint
        "non-existing endpoint"            | "/error"
        "non-existing actuator endpoint"   | "/actuator/error"
        "non-existing monitoring endpoint" | "/monitoring/error"
        "valid endpoint with uppercase"    | "/Validate"
    }

    @Story("Not allowed endpoints return error")
    def "Non-exposed Spring Boot actuator endpoint #endpoint is not allowed"() {
        expect: "non-exposed actuator endpoint is not be accessible"
        SivaRequests.get("/monitoring/" + endpoint).then().statusCode(HttpStatus.SC_NOT_FOUND)

        where:
        endpoint << [
                "beans", "caches", "conditions", "configprops", "env", "heapdump", "loggers",
                "mappings", "metrics", "scheduledtasks", "shutdown", "threaddump", "sbom", "logfile"
        ]
    }

    @Story("Not allowed endpoints return error")
    def "Non-exposed Spring Boot actuator discovery endpoint is not allowed: #endpoint"() {
        expect: "discovery endpoint is not accessible"
        SivaRequests.get(endpoint).then().statusCode(error)

        where:
        endpoint       | error
        "/monitoring"  | HttpStatus.SC_FORBIDDEN
        "/monitoring/" | HttpStatus.SC_NOT_FOUND
    }
}
