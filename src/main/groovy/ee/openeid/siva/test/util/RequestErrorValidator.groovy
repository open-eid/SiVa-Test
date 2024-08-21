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

package ee.openeid.siva.test.util

import ee.openeid.siva.test.model.RequestError
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.Matchers.hasSize

class RequestErrorValidator {
    static void validate(Response response, RequestError... expectedErrors) {
        response.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(expectedErrors.size()))

        expectedErrors.each { error ->
            response.then().body("requestErrors.findAll { requestError -> " +
                    "requestError.key == '${error.key}' && " +
                    "requestError.message == '${error.message}' }",
                    hasSize(1)
            )
        }
    }
}
