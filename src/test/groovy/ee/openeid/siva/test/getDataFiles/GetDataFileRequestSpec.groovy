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

package ee.openeid.siva.test.getDataFiles

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response

import static org.hamcrest.Matchers.is

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface")
class GetDataFileRequestSpec extends GenericSpecification {

    @Description("Request with empty body or empty values results in error")
    def "Given #comment, then error is returned"() {
        when:
        Response response = SivaRequests.tryGetDataFiles(body)

        then:
        RequestErrorValidator.validate(
                response,
                RequestError.DATA_FILE_FILENAME_INVALID,
                RequestError.DOCUMENT_BLANK,
                RequestError.DOCUMENT_INVALID_BASE_64
        )

        where:
        body                                | comment
        [:]                                 | "empty request body"
        RequestData.dataFileRequest("", "") | "empty request parameters"
    }

    @Description("Order of elements is changed in request")
    def "Given different order of request parameters, then request succeeds"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc")
        Map reversedRequestData = requestData.entrySet().toList().reverse().collectEntries()
        expect:
        SivaRequests.getDataFiles(reversedRequestData)
                .then()
                .body("dataFiles[0].filename", is("test.txt"))
                .body("dataFiles[0].mimeType", is("application/octet-stream"))
                .body("dataFiles[0].base64", is("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
                .body("dataFiles[0].size", is(24))
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
                .body("dataFiles[0].size", is(24))
                .body("dataFiles[0].base64", is("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
    }

    @Description("Requesting data files with missing mandatory body element results in error")
    def "Given #key parameter missing, then error is returned"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc")
        requestData.remove(key)

        when:
        Response response = SivaRequests.tryGetDataFiles(requestData)

        then:
        RequestErrorValidator.validate(response, *errors)

        where:
        key        | comment | errors
        "document" | ""      | [RequestError.DOCUMENT_BLANK, RequestError.DOCUMENT_INVALID_BASE_64]
        "filename" | ""      | [RequestError.DATA_FILE_FILENAME_INVALID]
    }

    @Description("Requesting data files from valid or invalid document with invalid (non-ddoc) type in filename returns error for invalid datafile filename")
    def "Given #comment, then data files request returns invalid datafile filename error"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile(document, filename)

        when:
        Response response = SivaRequests.tryGetDataFiles(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DATA_FILE_FILENAME_INVALID)

        where:
        document              | filename              | comment
        "BDOC-TS.bdoc"        | "BDOC-TS.bdoc"        | "bdoc document"
        "hellopades-lt-b.pdf" | "hellopades-lt-b.pdf" | "ddoc with .bdoc extension"
        "valid_XML1_3.ddoc"   | "valid_XML1_3.bdoc"   | "ddoc with .bdoc extension"
        "valid_XML1_3.ddoc"   | "valid_XML1_3.pdf"    | "ddoc with .pdf extension"
        "valid_XML1_3.ddoc"   | "valid_XML1_3.jpg"    | "ddoc with .jpg extension"
        "valid_XML1_3.ddoc"   | "valid_XML1_3.xroad"  | "ddoc with .xroad extension"

    }

    @Description("Requesting data files from non-ddoc document with ddoc type in filename returns error for document malformed or not matching documentType")
    def "Given #comment, then data files request returns 'Document malformed or not matching documentType' error"() {
        given:
        Map requestData = RequestData.dataFileRequestFromFile(document, filename)

        when:
        Response response = SivaRequests.tryGetDataFiles(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)

        where:
        document                      | filename                       | comment
        "BDOC-TS.bdoc"                | "BDOC-TS.ddoc"                 | "bdoc with .ddoc extension"
        "PdfValidSingleSignature.pdf" | "PdfValidSingleSignature.ddoc" | "pdf with .ddoc extension"
        "Picture.png"                 | "Picture.ddoc"                 | "png with .ddoc extension"
    }

    @Description("Datafiles request with request body of limit length succeeds")
    @Link("http://open-eid.github.io/SiVa/siva3/deployment_guide/#configuration-parameters")
    def "Given request with body of limit length, then data files request succeeds"() {
        expect:
        SivaRequests.getDataFiles(RequestData.requestWithFixedBodyLength(RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc"), conf.sivaRequestSizeLimit()))
                .then()
                .statusCode(200)
                .body("dataFiles[0].filename", is("test.txt"))
    }
}
