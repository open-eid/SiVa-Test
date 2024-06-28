package ee.openid.siva.test

import ee.openid.siva.test.util.AllureRestAssuredWithStep
import io.restassured.RestAssured

class BeforeAll {

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses in allure report
        RestAssured.filters(new AllureRestAssuredWithStep())
        // Limit console logging to failed tests only
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails()
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
    }
}
