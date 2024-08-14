package ee.openeid.siva.test.util

import groovy.transform.Canonical
import io.restassured.response.ValidatableResponse
import org.apache.http.HttpStatus

import static org.hamcrest.Matchers.hasSize

@Canonical
class RequestError {
    String key
    String message

    static void assertErrorResponse(ValidatableResponse response, RequestError... expectedErrors) {
        response
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(expectedErrors.length))

        expectedErrors.each { error ->
            response.body("requestErrors.findAll { requestError -> " +
                    "requestError.key == '${error.key}' && " +
                    "requestError.message == '${error.message}' }",
                    hasSize(1)
            )
        }
    }
}
