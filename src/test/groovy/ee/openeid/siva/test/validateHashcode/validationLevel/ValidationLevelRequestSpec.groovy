/*
 * Copyright 2024 - 2026 Riigi Infosüsteemi Amet
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


package ee.openeid.siva.test.validateHashcode.validationLevel

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.*
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.is

@Epic("Signature validation (hashcode)")
@Feature("Request validation (validation level)")
@Link("https://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface-for-hashcode")
class ValidationLevelRequestSpec extends GenericSpecification {

    @Story("Disallowed validation level is rejected")
    def "Given request with #description as validation level, then error is returned"() {
        given: "request body with disallowed validation level"
        Map requestData = validRequestBody()
        requestData.validationLevel = validationLevel

        when: "request is sent"
        Response response = SivaRequests.tryValidateHashcode(requestData)

        then: "request is rejected"
        RequestErrorValidator.validate(response, RequestError.VALIDATION_LEVEL_INVALID)

        where:
        description                   | validationLevel
        "Timestamps"                  | "Timestamps"
        "BasicSignatures"             | "BasicSignatures"
        "empty"                       | ""
        "unknown"                     | "NotValid"
        "surrounded by whitespace"    | " LongTermData "
        "containing inner whitespace" | "Long TermData"
    }

    @Story("Validation level is case insensitive")
    def "Given validation level '#validationLevel', then level is case insensitive"() {
        given: "request body with validation level"
        Map requestData = validRequestBody()
        requestData.validationLevel = validationLevel

        when: "request is sent"
        Response response = SivaRequests.tryValidateHashcode(requestData)

        then: "request is accepted"
        response.then().statusCode(HttpStatus.SC_OK)

        where:
        validationLevel << ["archivaldata", "ARCHIVALDATA", "ArChIvAlDaTa",
                            "longtermdata", "LONGTERMDATA", "LoNgTeRmDaTa"]
    }

    @Story("Null validation level falls back to the default")
    def "Given null validation level, then default validation level is used"() {
        given: "request body with null validation level"
        Map requestData = validRequestBody()
        requestData.validationLevel = null

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestData)

        then: "request is accepted and default validation level is used"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("ARCHIVAL_DATA"))
    }

    private static Map validRequestBody() {
        RequestData.hashcodeValidationRequest(
                MOCK_XADES_SIGNATURE_FILE,
                SignaturePolicy.POLICY_4,
                ReportType.SIMPLE,
                MOCK_XADES_DATAFILE_FILENAME,
                HashAlgo.SHA256,
                MOCK_XADES_DATAFILE_HASH
        )
    }
}
