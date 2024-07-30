package ee.openeid.siva.test

import ee.openeid.siva.test.util.AllureRestAssuredWithStep
import ee.openeid.siva.test.util.Utils
import io.restassured.RestAssured
import io.restassured.filter.Filter
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter

class BeforeAll {

    TestConfig conf = ConfigHolder.getConf()

    BeforeAll() {

        // Rest Assured settings
        // Log all requests and responses in allure report
//        RestAssured.filters(new AllureRestAssuredWithStep())
//         Temporary solution to prevent log duplication in Allure report. TODO: remove once JUnit tests are removed.
        addRestAssuredFilterSafely(new AllureRestAssuredWithStep())
        // Relax validation
        RestAssured.useRelaxedHTTPSValidation()
        // Log requests and responses to console for debugging
        // Enabled when not running in docker (i.e. running locally) or when toggled in configuration
        if (Utils.isLocal() || conf.restAssuredConsoleLogging()) {
//            RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
//             Temporary solution to prevent log duplication in Allure report. TODO: remove once JUnit tests are removed.
            addRestAssuredFilterSafely(new RequestLoggingFilter())
            addRestAssuredFilterSafely(new ResponseLoggingFilter())
        }
    }

    static void addRestAssuredFilterSafely(Filter filter) {
        if (RestAssured.filters().stream().noneMatch { f -> (f.metaClass.theClass.name == filter.metaClass.theClass.name) }) {
            RestAssured.filters(filter)
        }
    }
}
