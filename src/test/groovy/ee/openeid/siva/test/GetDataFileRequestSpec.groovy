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
package ee.openeid.siva.test

import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestError
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.ValidatableResponse
import org.hamcrest.Matchers

import static ee.openeid.siva.integrationtest.TestData.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface")
class GetDataFileRequestSpec extends GenericSpecification {

    @Description("Input empty values")
    def "Given empty request parameters, then error is returned"() {
        when:
        ValidatableResponse response = SivaRequests.tryGetDataFiles(RequestData.dataFileRequest("", "")).then()

        then:
        List errors = [
                new Tuple(FILENAME, INVALID_DATA_FILE_FILENAME),
                new Tuple(DOCUMENT, MUST_NOT_BE_BLANK),
                new Tuple(DOCUMENT, INVALID_BASE_64)
        ]
        RequestError.assertErrorResponse(response, *errors.collect { errorType, error -> new RequestError(errorType, error) })
    }

    @Description("Totally empty request body is sent")
    def "Given empty request body, then error is returned"() {
        when:
        ValidatableResponse response = SivaRequests.tryGetDataFiles([:]).then()

        then:
        List errors = [
                new Tuple(FILENAME, INVALID_DATA_FILE_FILENAME),
                new Tuple(DOCUMENT, MUST_NOT_BE_BLANK),
                new Tuple(DOCUMENT, INVALID_BASE_64)
        ]
        RequestError.assertErrorResponse(response, *errors.collect { errorType, error -> new RequestError(errorType, error) })
    }

    @Description("Order of elements is changed in request")
    def "Given different order of request parameters, then request succeeds"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc")
        Map reversedRequestData = requestData.entrySet().toList().reverse().collectEntries()
        expect:
        SivaRequests.getDataFiles(reversedRequestData)
                .then()
                .body("dataFiles[0].filename", Matchers.is("test.txt"))
                .body("dataFiles[0].mimeType", Matchers.is("application/octet-stream"))
                .body("dataFiles[0].base64", Matchers.is("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
                .body("dataFiles[0].size", Matchers.is(24))
    }

    @Description("Extra request parameters are ignored")
    def "Given extra parameters in request, then extra parameters are ignored"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc")
        requestData.extraOne = "RandomValue"
        requestData.extraTwo = "AnotherValue"
        expect:
        SivaRequests.getDataFiles(requestData)
                .then()
                .body("dataFiles[0].size", Matchers.is(24))
                .body("dataFiles[0].base64", Matchers.is("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
    }

    @Description("Mandatory element 'document' is deleted")
    def "Given 'document' parameter missing, then error is returned"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc")
        requestData.remove("document")

        when:
        ValidatableResponse response = SivaRequests.tryGetDataFiles(requestData).then()

        then:
        List errors = [MUST_NOT_BE_BLANK, INVALID_BASE_64]
        RequestError.assertErrorResponse(response, *errors.collect { error -> new RequestError(DOCUMENT, error) })
    }

    @Description("Document type in filename differs from document (ddoc)")
    def "Given #comment, then invalid datafile filename error is returned"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile(document, filename)

        when:
        ValidatableResponse response = SivaRequests.tryGetDataFiles(requestData).then()

        then:
        RequestError.assertErrorResponse(response, new RequestError(FILENAME, INVALID_DATA_FILE_FILENAME))

        where:
        document            | filename             | comment
        "valid_XML1_3.ddoc" | "valid_XML1_3.bdoc"  | "ddoc with .bdoc extension"
        "valid_XML1_3.ddoc" | "valid_XML1_3.pdf"   | "ddoc with .pdf extension"
        "valid_XML1_3.ddoc" | "valid_XML1_3.jpg"   | "ddoc with .jpg extension"
        "valid_XML1_3.ddoc" | "valid_XML1_3.xroad" | "ddoc with .xroad extension"

    }

    @Description("Document type in filename differs from document")
    def "Given #comment, then 'Document malformed or not matching documentType'"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile(document, filename)

        when:
        ValidatableResponse response = SivaRequests.tryGetDataFiles(requestData).then()

        then:
        RequestError.assertErrorResponse(response, new RequestError(DOCUMENT, DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE))

        where:
        document                      | filename                       | comment
        "BDOC-TS.bdoc"                | "BDOC-TS.ddoc"                 | "bdoc with .ddoc extension"
        "PdfValidSingleSignature.pdf" | "PdfValidSingleSignature.ddoc" | "pdf with .ddoc extension"
        "Picture.png"                 | "Picture.ddoc"                 | "png with .ddoc extension"
    }

    @Description("Datafiles request with request body of limit length")
    @Link("http://open-eid.github.io/SiVa/siva3/deployment_guide/#configuration-parameters")
    def "Given request body of limit length, then valid response is returned"() {
        expect:
        SivaRequests.getDataFiles(RequestData.requestWithFixedBodyLength(RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc"), SIVA_FILE_SIZE_LIMIT))
                .then()
                .statusCode(200)
                .body("dataFiles[0].filename", Matchers.is("test.txt"))
    }
}
