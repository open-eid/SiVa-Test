package ee.openid.siva.test

import ee.openid.siva.test.util.AllureRestAssuredWithStep
import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

class BeforeAll {

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses locally and in allure report
        RestAssured.filters(new AllureRestAssuredWithStep(), new RequestLoggingFilter(), new ResponseLoggingFilter())
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
    }
}
