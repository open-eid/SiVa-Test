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

import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response

import static ee.openeid.siva.integrationtest.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.equalTo

@Link("http://open-eid.github.io/SiVa/siva3/overview/#main-features-of-siva-validation-service")
class LargeFileSpec extends GenericSpecification {

    @Description("9MB PDF files (PAdES Baseline LT).")
    def "pdfNineMegabyteFilesWithLtSignatureAreAccepted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("9MB_PDF.pdf", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.PAdES_BASELINE_LT))
                .body("validatedDocument.filename", equalTo("9MB_PDF.pdf"))
    }

    @Description("9MB ASIC-E file")
    def "bdocTsNineMegabyteFilesValidSignatureAreAccepted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("9MB_BDOC-TS.bdoc", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.XAdES_BASELINE_LT))
                .body("validatedDocument.filename", equalTo("9MB_BDOC-TS.bdoc"))
                .body("validSignaturesCount", equalTo(1))
    }

    @Description("9MB BDOC-TM")
    def "bdocTmNineMegabyteFilesValidSignatureAreAccepted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("9MB_BDOC-TM.bdoc", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("validatedDocument.filename", equalTo("9MB_BDOC-TM.bdoc"))
                .body("validSignaturesCount", equalTo(1))
    }

    @Description("9MB DDOC")
    def "ddocTenMegabyteFilesWithValidSignatureAreAccepted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("9MB_DDOC.ddoc", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.DIGIDOC_XML_1_3))
                .body("validatedDocument.filename", equalTo("9MB_DDOC.ddoc"))
                .body("validSignaturesCount", equalTo(1))
    }

    @Description("Bdoc Zip container with Bomb file")
    def "bdocZipBombsAreNotAccepted"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest(
                "zip-bomb-package-zip-1gb.bdoc", SignaturePolicy.POLICY_3.name))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Asice Zip container with Bomb file")
    def "asiceZipBombsAreNotAccepted"() {
        given:
        Map requestData = RequestData.validationRequest("zip-bomb-package-zip-1gb.bdoc", SignaturePolicy.POLICY_3.name)
        requestData.filename = "zip-bomb-package-zip-1gb.asice"

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Asice Zip container with Matryoshka Bomb file")
    def "asiceZipBombsWithMatryoshkaAreAccepted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("zip-bomb-packages.asice", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.XAdES_BASELINE_B))
                .body("validatedDocument.filename", equalTo("zip-bomb-packages.asice"))
                .body("validSignaturesCount", equalTo(0))
    }

    @Description("Bdoc Zip container with Matryoshka Bomb file")
    def "bdocZipBombsWithMatryoshkaAreAccepted"() {
        when:
        Map requestData = RequestData.validationRequest("zip-bomb-packages.asice", SignaturePolicy.POLICY_3.name)
        requestData.filename = "zip-bomb-packages.bdoc"

        then:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.XAdES_BASELINE_B_BES))
                .body("validatedDocument.filename", equalTo("zip-bomb-packages.bdoc"))
                .body("validSignaturesCount", equalTo(0))
    }

    @Description("Asics Zip container with Bomb file")
    def "asicsZipBombsAreNotAccepted"() {
        given:
        Map requestData = RequestData.validationRequest("zip-bomb-package-zip-1gb-asics.asics", SignaturePolicy.POLICY_3.name)
        requestData.filename = "zip-bomb-package-zip-1gb.asics"

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }
}
