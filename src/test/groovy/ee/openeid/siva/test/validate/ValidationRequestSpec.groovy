/*
 * Copyright 2024 - 2025 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test.validate

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.RestAssured
import io.restassured.http.ContentType
import io.restassured.http.Method
import io.restassured.response.Response
import io.restassured.specification.RequestSpecification
import org.apache.commons.codec.binary.Base64
import org.apache.http.HttpStatus
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
class ValidationRequestSpec extends GenericSpecification {

    @Description("Supported file extensions")
    def "Given validation request with #extension file, then validation report is returned"() {
        given:
        Map requestData = RequestData.validationRequest(file, extension)
        expect:
        SivaRequests.validate(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validatedDocument.filename", equalTo(requestData.filename))

        where:
        extension | file
        "asice"   | "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"
        "asics"   | "TEST_ESTEID2018_ASiC-S_XAdES_LT.scs"
        "bdoc"    | "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"
        "ddoc"    | "valid_XML1_3.ddoc"
        "pdf"     | "TEST_ESTEID2018_PAdES_LT_enveloped.pdf"
        "sce"     | "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"
        "scs"     | "TEST_ESTEID2018_ASiC-S_XAdES_LT.scs"
        "p7m"     | "TEST_ESTEID2018_CAdES_LT_enveloping.p7m"
        "p7s"     | "TEST_ESTEID2018_CAdES_LT_detached.p7s"
    }

    @Description("All standalone signature profiles are validated")
    def "Given validation request with #profile #packaging signature, then validation report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validatedDocument.filename", equalTo(file))
                .body("signatures[0].signatureFormat", is(profile))

        where:
        profile                            | packaging    | file
        // CAdES
        SignatureFormat.CAdES_BASELINE_B   | "detached"   | "TEST_ESTEID2018_CAdES_B_detached.p7s"
        SignatureFormat.CAdES_BASELINE_B   | "enveloping" | "TEST_ESTEID2018_CAdES_B_enveloping.p7m"
        SignatureFormat.CAdES_BASELINE_T   | "detached"   | "TEST_ESTEID2018_CAdES_T_detached.p7s"
        SignatureFormat.CAdES_BASELINE_T   | "enveloping" | "TEST_ESTEID2018_CAdES_T_enveloping.p7m"
        SignatureFormat.CAdES_BASELINE_LT  | "detached"   | "TEST_ESTEID2018_CAdES_LT_detached.p7s"
        SignatureFormat.CAdES_BASELINE_LT  | "enveloping" | "TEST_ESTEID2018_CAdES_LT_enveloping.p7m"
        SignatureFormat.CAdES_BASELINE_LTA | "detached"   | "TEST_ESTEID2018_CAdES_LTA_detached.p7s"
        SignatureFormat.CAdES_BASELINE_LTA | "enveloping" | "TEST_ESTEID2018_CAdES_LTA_enveloping.p7m"
        // PAdES
        SignatureFormat.PAdES_BASELINE_B   | "enveloped"  | "TEST_ESTEID2018_PAdES_B_enveloped.pdf"
        SignatureFormat.PAdES_BASELINE_T   | "enveloped"  | "TEST_ESTEID2018_PAdES_T_enveloped.pdf"
        SignatureFormat.PAdES_BASELINE_LT  | "enveloped"  | "TEST_ESTEID2018_PAdES_LT_enveloped.pdf"
        SignatureFormat.PAdES_BASELINE_LTA | "enveloped"  | "TEST_ESTEID2018_PAdES_LTA_enveloped.pdf"
        // XAdES
        SignatureFormat.XAdES_BASELINE_B   | "detached"   | "TEST_ESTEID2018_XAdES_B_detached.xml"
        SignatureFormat.XAdES_BASELINE_B   | "enveloped"  | "TEST_ESTEID2018_XAdES_B_enveloped.xml"
        SignatureFormat.XAdES_BASELINE_B   | "enveloping" | "TEST_ESTEID2018_XAdES_B_enveloping.xml"
        SignatureFormat.XAdES_BASELINE_T   | "detached"   | "TEST_ESTEID2018_XAdES_T_detached.xml"
        SignatureFormat.XAdES_BASELINE_T   | "enveloped"  | "TEST_ESTEID2018_XAdES_T_enveloped.xml"
        SignatureFormat.XAdES_BASELINE_T   | "enveloping" | "TEST_ESTEID2018_XAdES_T_enveloping.xml"
        SignatureFormat.XAdES_BASELINE_LT  | "detached"   | "TEST_ESTEID2018_XAdES_LT_detached.xml"
        SignatureFormat.XAdES_BASELINE_LT  | "enveloped"  | "TEST_ESTEID2018_XAdES_LT_enveloped.xml"
        SignatureFormat.XAdES_BASELINE_LT  | "enveloping" | "TEST_ESTEID2018_XAdES_LT_enveloping.xml"
        SignatureFormat.XAdES_BASELINE_LTA | "detached"   | "TEST_ESTEID2018_XAdES_LTA_detached.xml"
        SignatureFormat.XAdES_BASELINE_LTA | "enveloped"  | "TEST_ESTEID2018_XAdES_LTA_enveloped.xml"
        SignatureFormat.XAdES_BASELINE_LTA | "enveloping" | "TEST_ESTEID2018_XAdES_LTA_enveloping.xml"
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
    def "Given request body with invalid key #newKey, then error is returned"() {
        given:
        Map requestData = RequestData.validationRequest("singleValidSignatureTM.bdoc")
        requestData.put(newKey, requestData.remove(originalKey))
        when:
        Response response = SivaRequests.tryValidate(requestData)

        then:
        RequestErrorValidator.validate(response, *errors)

        where:
        originalKey | newKey     | errors
        "document"  | "DOCUMENT" | [RequestError.DOCUMENT_BLANK, RequestError.DOCUMENT_INVALID_BASE_64]
        "filename"  | "FILENAME" | [RequestError.FILENAME_EMPTY, RequestError.FILENAME_INVALID]
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
                .header("Content-Disposition", is("attachment; filename=\"api.json\""))
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
        response.then().header("Content-Disposition", is("attachment; filename=\"api.json\""))

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
                .body("validSignaturesCount", is(1))
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
        response.then().header("Content-Disposition", is("attachment; filename=\"api.json\""))

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
                .body("requestErrors[0].key", is("request"))
                .body("requestErrors[0].message", is(errorMessage))
    }

    @Description("Validation response includes Content-Disposition header")
    def "Given validate request, then response includes Content-Disposition header"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTM.bdoc"))
                .then()
                .header("Content-Disposition", is("attachment; filename=\"api.json\""))
    }

    @Description("Validation endpoint checks")
    def "Validation request with method #method is #result"() {
        given:
        RequestSpecification request = given()
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(RequestData.validationRequest("singleValidSignatureTM.bdoc"))
                .contentType(ContentType.JSON)
                .baseUri(SivaRequests.sivaServiceUrl)
                .basePath("/validate")

        when:
        Response response = request.request(method)

        then:
        response.then().statusCode(httpStatus)

        where:
        method         || httpStatus                       | result
        Method.GET     || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
        Method.PUT     || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
        Method.POST    || HttpStatus.SC_OK                 | "allowed"
        Method.DELETE  || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
        Method.HEAD    || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
        Method.TRACE   || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
        Method.OPTIONS || HttpStatus.SC_OK                 | "allowed"
        Method.PATCH   || HttpStatus.SC_METHOD_NOT_ALLOWED | "not allowed"
    }
}
