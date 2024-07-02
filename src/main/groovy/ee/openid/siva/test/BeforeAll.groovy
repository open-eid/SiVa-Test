package ee.openid.siva.test

import ee.openid.siva.test.util.AllureRestAssuredWithStep
import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

class BeforeAll {

    TestConfig conf = ConfigHolder.getConf()

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses in allure report
        RestAssured.filters(new AllureRestAssuredWithStep())
        // Limit console logging to failed tests only
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails()
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
        // Log requests and responses to console for debugging
        if (conf.restAssuredConsoleLogging()) {
            RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
        }
    }
}
