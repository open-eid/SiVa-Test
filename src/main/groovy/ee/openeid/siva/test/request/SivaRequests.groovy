package ee.openeid.siva.test.request

import ee.openeid.siva.test.ConfigHolder
import ee.openeid.siva.test.TestConfig
import io.qameta.allure.Step
import io.restassured.http.ContentType
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static io.restassured.RestAssured.given

class SivaRequests {

    static TestConfig conf = ConfigHolder.getConf()
    static String sivaServiceUrl = "${conf.sivaProtocol()}://${conf.sivaHostname()}:${conf.sivaPort()}${conf.sivaContextPath()}"

    @Step("POST {endpoint}")
    static Response post(String endpoint, Map data) {
        return given()
//                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(data)
                .contentType(ContentType.JSON)
                .when()
                .post(sivaServiceUrl + endpoint)
    }

    @Step("GET {endpoint}")
    static Response get(String endpoint) {
        return given()
//                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .contentType(ContentType.JSON)
                .when()
                .get(sivaServiceUrl + endpoint)
    }

    static Response tryValidate(Map data) {
        return post("/validate", data)
    }

    @Step("Validate")
    static Response validate(Map data) {
        Response response = tryValidate(data)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    static Response tryGetDataFiles(Map data) {
        return post("/getDataFiles", data)
    }

    @Step("Get data files")
    static Response getDataFiles(Map data) {
        Response response = tryGetDataFiles(data)
        response.then().statusCode(HttpStatus.SC_OK)
        return response
    }

    static Response tryValidateHashcode(Map data) {
        return post("/validateHashcode", data)
    }

    @Step("Validate hashcode")
    static Response validateHashcode(Map data) {
        Response response = tryValidateHashcode(data)
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
