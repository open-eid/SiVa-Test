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


import ee.openeid.siva.test.model.ReportType
import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response
import org.apache.commons.codec.binary.Base64
import org.apache.http.HttpStatus
import org.hamcrest.Matchers
import spock.lang.Ignore

import static ee.openeid.siva.integrationtest.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
class ValidationRequestSpec extends GenericSpecification {

    @Description("Validation request happy path")
    def "Given validation request, then validation report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTM.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validatedDocument.filename", equalTo("singleValidSignatureTM.bdoc"))
                .body("validSignaturesCount", equalTo(1))
    }

    @Description("Totally empty request body is sent")
    def "Given validation request with empty body, then error is returned"() {
        when:
        Response response = SivaRequests.tryValidate([:])

        then:
        RequestErrorValidator.validate(
                response,
                RequestError.DOCUMENT_BLANK,
                RequestError.DOCUMENT_INVALID_BASE_64,
                RequestError.FILENAME_EMPTY,
                RequestError.FILENAME_INVALID
        )
    }


    @Description("Extra request parameters are ignored")
    def "Given extra parameters in validation request, then extra parameters are ignored"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData.extraOne = "RandomValue"
        requestData.extraTwo = "AnotherValue"

        expect:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validatedDocument.filename", equalTo("singleValidSignatureTM.bdoc"))
    }

    @Description("Request has invalid keys (capital letters)")
    def "Given request body with invalid keys, then error is returned"() {
        given:
        Map requestData = [
                DOCUMENT: Base64.encodeBase64String(Utils.readFileFromResources("singleValidSignatureTM.bdoc")),
                FILENAME: "singleValidSignatureTM.bdoc",
        ]

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(
                response,
                RequestError.DOCUMENT_BLANK,
                RequestError.DOCUMENT_INVALID_BASE_64,
                RequestError.FILENAME_EMPTY,
                RequestError.FILENAME_INVALID
        )
    }

    @Description("Invalid input")
    def "Given request with #comment, then error is returned"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData[key] = value

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, *errors)

        where:
        key               | value               | comment                           | errors
        "document"        | ""                  | "document parameter empty"        | [RequestError.DOCUMENT_BLANK, RequestError.DOCUMENT_INVALID_BASE_64]
        "document"        | "aaa"               | "malformed base64 as document"    | [RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE]
        "document"        | ",:"                | "not base64 as document"          | [RequestError.DOCUMENT_INVALID_BASE_64]
        "filename"        | ""                  | "filename parameter empty"        | [RequestError.FILENAME_EMPTY, RequestError.FILENAME_INVALID_SIZE]
        "filename"        | "a" * 256 + ".bdoc" | "filename too long"               | [RequestError.FILENAME_INVALID_SIZE]
        "signaturePolicy" | ""                  | "signaturePolicy parameter empty" | [RequestError.SIGNATURE_POLICY_INVALID_SIZE]
        "signaturePolicy" | "a" * 101           | "signaturePolicy too long"        | [RequestError.SIGNATURE_POLICY_INVALID_SIZE]
        "reportType"      | ""                  | "reportType parameter empty"      | [RequestError.REPORT_TYPE_INVALID]
        "reportType"      | "NotValid"          | "invalid reportType"              | [RequestError.REPORT_TYPE_INVALID]
    }

    @Description("Filename valid values")
    def "Validation request filename field #comment"() {
        given:
        Map requestData = [
                document: Base64.encodeBase64String(Utils.readFileFromResources("singleValidSignatureTM.bdoc")),
                filename: value,
        ]

        expect:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", equalTo(1))

        where:
        value                          | comment
        "singleValidSignatureTM.bDoC"  | "case insensitive"
        "singleValidSignatureTM .bdoc" | "ignores spaces"
        "a" * 255 + ".bdoc"            | "in allowed length"
    }


    @Description("Correct signature policy usage")
    def "Given signature policy #condition, then #expected"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData.signaturePolicy = policy
        expect:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyName", equalTo(expectedPolicy))

        where:
        policy                        | expectedPolicy                | condition | expected
        SignaturePolicy.POLICY_3.name | SignaturePolicy.POLICY_3.name | "POLv3"   | "correct policy is returned"
        SignaturePolicy.POLICY_4.name | SignaturePolicy.POLICY_4.name | "POLv4"   | "correct policy is returned"
        null                          | SignaturePolicy.POLICY_4.name | "missing" | "default policy is used"
    }

    @Description("Not available signature policy")
    def "Given not available signature policy, then error is returned"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData.signaturePolicy = "POLv2"

        when:
        Response response = SivaRequests.tryValidate(requestData)
        then:
        response.then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(1))
                .body("requestErrors.findAll { requestError -> " +
                        "requestError.key == 'signaturePolicy' && " +
                        "requestError.message == 'Invalid signature policy: POLv2; Available abstractPolicies: [POLv3, POLv4]' }",
                        hasSize(1)
                )
    }

    @Description("Invalid signature policy")
    def "Given signature policy #comment, then error is returned"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData.signaturePolicy = policy

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, errors)


        where:
        policy    | comment               | errors
        "POLv3.*" | "in incorrect format" | RequestError.SIGNATURE_POLICY_INVALID
        ""        | "empty"               | RequestError.SIGNATURE_POLICY_INVALID_SIZE
        'a' * 101 | "too long"            | RequestError.SIGNATURE_POLICY_INVALID_SIZE
    }

    @Description("")
    def "Given report type #condition, then #result"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTS.asice")
        requestData.reportType = reportType
        expect:
        SivaRequests.validate(requestData)
                .then()
                .body("validationReport.validationProcess", emptyOrNullString())
                .body("validationReport.validationConclusion.validSignaturesCount", equalTo(1))

        where:
        reportType | condition       | result
        null       | "missing"       | "default report type is used"
        "SiMpLe"   | "in mixed case" | "report type is case insensitive"
    }

    @Description("ReportType parameter Simple")
    def "Given reportType simple, then simple report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTS.asice", null, ReportType.SIMPLE))
                .then()
                .body("validationReport.validationProcess", emptyOrNullString())
                .body("validationReport.diagnosticData", emptyOrNullString())
                .body(VALIDATION_CONCLUSION_PREFIX + "validSignaturesCount", equalTo(1))
    }

    @Description("ReportType parameter Detailed")
    def "Given reportType detailed, then detailed report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTS.asice", null, ReportType.DETAILED))
                .then()
                .body("validationReport.diagnosticData", emptyOrNullString())
                .body("validationReport.validationProcess.signatureOrTimestampOrEvidenceRecord[0].validationSignatureQualification.signatureQualification", equalTo(SignatureLevel.QESIG))
                .body(VALIDATION_CONCLUSION_PREFIX + "validSignaturesCount", equalTo(1))
    }

    @Description("ReportType parameter Diagnostic")
    def "Given reportType diagnostic, then diagnostic report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTS.asice", null, ReportType.DIAGNOSTIC))
                .then()
                .body("validationReport.validationProcess", emptyOrNullString())
                .body("validationReport.diagnosticData.documentName", equalTo("singleValidSignatureTS.asice"))
                .body(VALIDATION_CONCLUSION_PREFIX + "validSignaturesCount", equalTo(1))
    }

    @Description("DocumentType parameter is not allowed")
    def "Given documentType parameter, then error is returned"() {
        given:
        Map requestData = RequestData.validationRequest("xroad-simple.asice")
        requestData.documentType = "xroad"

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_TYPE_INVALID)
    }

    @Description("Mismatch in stated and actual document resulting in error: 'Document malformed or not matching documentType'")
    def "Given #comment, then 'Document malformed or not matching documentType'"() {
        given:
        Map requestData = RequestData.validationRequest(document)
        requestData.filename = filename

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)

        where:
        document                       | filename                      | comment
        "singleValidSignatureTM.bdoc"  | "singleValidSignatureTM.ddoc" | "bdoc with .ddoc extension"
        "PdfValidSingleSignature.pdf"  | "dfValidSingleSignature.bdoc" | "pdf with .bdoc extension"
        "PdfValidSingleSignature.pdf"  | "dfValidSingleSignature.ddoc" | "pdf with .ddoc extension"
        "singleValidSignatureTS.asice" | "singleValidSignatureTS.ddoc" | "asice with .ddoc extension"
        "TXTinsideAsics.asics"         | "TXTinsideAsics.ddoc"         | "asics with .ddoc extension"

        // Combinations not resulting in 'Document malformed or not matching documentType' error, FOR manual quick-check
//        "singleValidSignatureTM.bdoc"  | "singleValidSignatureTM.pdf"   | ""
//        "singleValidSignatureTM.bdoc"  | "singleValidSignatureTM.asice" | ""
//        "singleValidSignatureTM.bdoc"  | "singleValidSignatureTM.asics" | ""
//        "PdfValidSingleSignature.pdf"  | "dfValidSingleSignature.asice" | ""
//        "PdfValidSingleSignature.pdf"  | "dfValidSingleSignature.asics" | ""
//        "18912.ddoc"                   | "18912.bdoc"                   | ""
//        "18912.ddoc"                   | "18912.pdf"                    | ""
//        "18912.ddoc"                   | "18912.asice"                  | ""
//        "18912.ddoc"                   | "18912.asics"                  | ""
//        "singleValidSignatureTS.asice" | "singleValidSignatureTS.bdoc"  | ""
//        "singleValidSignatureTS.asice" | "singleValidSignatureTS.pdf"   | ""
//        "singleValidSignatureTS.asice" | "singleValidSignatureTS.asics" | ""
//        "TXTinsideAsics.asics"         | "TXTinsideAsics.bdoc"          | ""
//        "TXTinsideAsics.asics"         | "TXTinsideAsics.pdf"           | ""
//        "TXTinsideAsics.asics"         | "TXTinsideAsics.asice"         | ""
    }

    @Description("Acceptance of ASICE as BDOC document type")
    def "Given asice document with bdoc extension, then asice files are handled the same as bdoc"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTS.asice")
        requestData.filename = "singleValidSignatureTS.bdoc"
        expect:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Input random base64 string as document")
    def "Given random base64 string as #extension, then 'Document malformed or not matching documentType'"() {
        given:
        Map requestData = [
                document: "ZCxTgQxDET7/lNizNZ4hrB1Ug8I0kKpVDkHEgWqNjcKFMD89LsIpdCkpUEsFBgAAAAAFAAUAPgIAAEM3AAAAAA==",
                filename: "some_file." + extension,
        ]

        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)

        where:
        extension | _
        "bdoc"    | _
        "ddoc"    | _
        "pdf"     | _
    }

    @Description("Validation request with request body of limit length")
    @Link("http://open-eid.github.io/SiVa/siva3/deployment_guide/#configuration-parameters")
    def "Given request body of limit length, then validation report is returned"() {
        expect:
        SivaRequests.validate(
                RequestData.requestWithFixedBodyLength(
                        RequestData.validationRequest("singleValidSignatureTS.asice"),
                        conf.sivaRequestSizeLimit()))
                .then()
                .statusCode(200)
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
    }

    @Ignore("SIVA-641")
    @Description("Validation request with request body length over limit")
    @Link("http://open-eid.github.io/SiVa/siva3/deployment_guide/#configuration-parameters")
    def "Given request body over limit length, then error is returned"() {
        expect:
        String errorMessageTemplate = "Request content-length (%s bytes) exceeds request size limit (%s bytes)"
        String errorMessage = String.format(errorMessageTemplate, conf.sivaRequestSizeLimit() + 1, conf.sivaRequestSizeLimit())
        SivaRequests.validate(
                RequestData.requestWithFixedBodyLength(
                        RequestData.validationRequest("singleValidSignatureTS.asice"),
                        conf.sivaRequestSizeLimit() + 1))
                .then()
                .statusCode(400)
                .body("requestErrors[0].key", Matchers.is("request"))
                .body("requestErrors[0].message", Matchers.is(errorMessage))
    }
}
