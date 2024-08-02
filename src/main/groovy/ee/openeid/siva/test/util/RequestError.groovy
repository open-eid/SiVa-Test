package ee.openeid.siva.test.util

import groovy.transform.Canonical
import io.restassured.response.ValidatableResponse
import org.apache.http.HttpStatus

import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.hasSize

@Canonical
class RequestError {
    String key
    String message

    static void assertErrorResponse(ValidatableResponse response, RequestError... requestErrors) {
        response
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(requestErrors.length))

        for (RequestError requestError : requestErrors) {
            response.body("requestErrors.findAll { requestError -> " +
                    "requestError.key == '" + requestError.getKey() + "' && " +
                    "requestError.message=='" + requestError.getMessage() + "' }", hasSize(1))
        }
    }
}
