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

package ee.openeid.siva.test.request

import ee.openeid.siva.test.ConfigHolder
import ee.openeid.siva.test.TestConfig
import io.qameta.allure.Step
import io.restassured.RestAssured
import io.restassured.http.ContentType
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class SivaRequests {

    static TestConfig conf = ConfigHolder.getConf()
    static String sivaServiceUrl = "${conf.sivaProtocol()}://${conf.sivaHostname()}:${conf.sivaPort()}${conf.sivaContextPath()}"

    @Step("POST {endpoint}")
    static Response post(String endpoint, Map requestBody) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .contentType(ContentType.JSON)
                .when()
                .post(sivaServiceUrl + endpoint)
    }

    @Step("POST {endpoint}")
    static Response post(String endpoint, String requestBody) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .contentType(ContentType.JSON)
                .when()
                .post(sivaServiceUrl + endpoint)
    }

    @Step("GET {endpoint}")
    static Response get(String endpoint) {
        return given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .contentType(ContentType.JSON)
                .when()
                .get(sivaServiceUrl + endpoint)
    }

    static Response tryValidate(Map requestBody) {
        return post("/validate", requestBody)
    }

    @Step("Validate")
    static Response validate(Map requestBody) {
        Response response = tryValidate(requestBody)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    static Response tryGetDataFiles(Map requestBody) {
        return post("/getDataFiles", requestBody)
    }

    @Step("Get data files")
    static Response getDataFiles(Map requestBody) {
        Response response = tryGetDataFiles(requestBody)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    static Response tryValidateHashcode(Map requestBody) {
        return post("/validateHashcode", requestBody)
    }

    static Response tryValidateHashcode(String requestBody) {
        return post("/validateHashcode", requestBody)
    }

    @Step("Validate hashcode")
    static Response validateHashcode(Map requestBody) {
        Response response = tryValidateHashcode(requestBody)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Get Monitoring Health")
    static Response getMonitoringHealth() {
        Response response = get("/monitoring/health")
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Get Monitoring Heartbeat")
    static Response getMonitoringHeartbeat() {
        Response response = get("/monitoring/heartbeat")
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    @Step("Get Monitoring Version")
    static Response getMonitoringVersion() {
        Response response = get("/monitoring/version")
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }
}
