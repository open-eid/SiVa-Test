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

import ee.openeid.siva.test.allure.SivaRequirement

import static io.restassured.RestAssured.given

class SoapEndpointsDeprecatedSpec extends GenericSpecification {

    @SivaRequirement("interfaces")
    def "Soap #endpoint endpoint deprecated"() {
        given:
        String sivaServiceUrl = "${conf.sivaProtocol()}://${conf.sivaHostname()}:${conf.sivaPort()}${conf.sivaContextPath()}"

        expect:
        given()
                .contentType("text/xml;charset=UTF-8")
                .body("<test></test>")
                .when()
                .post(sivaServiceUrl + "/soap/" + endpoint)
                .then()
                .statusCode(404)

        where:
        endpoint                       | _
        "validationWebService"         | _
        "hashcodeValidationWebService" | _
        "dataFilesWebService"          | _
    }
}
