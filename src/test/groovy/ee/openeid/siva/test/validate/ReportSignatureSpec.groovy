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

package ee.openeid.siva.test.validate

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureLevel
import io.qameta.allure.Description
import io.restassured.RestAssured
import io.restassured.config.EncoderConfig
import io.restassured.http.ContentType
import io.restassured.response.Response
import org.apache.commons.codec.binary.Base64
import spock.lang.Ignore

import java.nio.file.FileSystems
import java.nio.file.Files

import static io.restassured.RestAssured.given
import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat

@Ignore("SIVA-196")
//Class disabled - feature not implemented
class ReportSignatureSpec extends GenericSpecification {
    private static final String VALIDATION_ENDPOINT = "/validate"
    protected static final String VALID_SIGNATURE_POLICY_4 = "POLv4"
    private static final String TEST_FILE_BASE = "src/test/resources/"

    private Response response


    /**
     * TestCaseID: Detailed-Report-Signatures-2
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_LTA signed with RSA key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportRsaSignatureXadesBaselineLTA"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat"), equalTo(SignatureFormat.XAdES_BASELINE_LTA))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureLevel"), equalTo(SignatureLevel.QESIG))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-3
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_LT signed with RSA key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportRsaSignatureXadesBaselineLT"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat"), equalTo(SignatureFormat.XAdES_BASELINE_LT))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureLevel"), equalTo(SignatureLevel.QESIG))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-4
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_T signed with RSA key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportRsaSignatureXadesBaselineT"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo(SignatureFormat.XAdES_BASELINE_T))

    }

    /**
     * TestCaseID: Detailed-Report-Signatures-5
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_B signed with RSA key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportRsaSignatureXadesBaselineB"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo(SignatureFormat.XAdES_BASELINE_B))
    }


    /**
     * TestCaseID: Detailed-Report-Signatures-6
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_LTA and signed with ECC key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportEccSignatureXadesBaselineLTA"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat"), equalTo(SignatureFormat.XAdES_BASELINE_LTA))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureLevel"), equalTo(SignatureLevel.QESIG))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-7
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_LT and signed with ECC key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportEccSignatureXadesBaselineLT"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat"), equalTo(SignatureFormat.XAdES_BASELINE_LT))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureLevel"), equalTo(SignatureLevel.QESIG))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-8
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_T and signed with ECC key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportEccSignatureXadesBaselineT"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo(SignatureFormat.XAdES_BASELINE_T))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-9
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when SignatureLevel XAdES_BASELINE_B and signed with ECC key.
     *
     * Expected Result: validationReportSignature exists in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportEccSignatureXadesBaselineB"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo(SignatureFormat.XAdES_BASELINE_B))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-10
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when configuration parameter OcspUrl empty
     *
     * Expected Result: No signature
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */

    @Description("")
    def "validateDetailedReportSignatureOcspUrlValueEmpty"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-11
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when configuration parameter TspUrl empty
     *
     * Expected Result: No signature
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Description("")
    def "validateDetailedReportSignatureTspUrlValueEmpty"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-12
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when configuration parameter Pkcs11 wrong value
     *
     * Expected Result: Error message
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Ignore
    @Description("")
    def "validateDetailedReportSignaturePkcs11WrongCert"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
        String validationReportSignature = response.jsonPath().getString("validationReportSignature")
        Map requestBody = [
                document: validationReportSignature,
                filename: "filename.pdf"
        ]
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(VALIDATION_ENDPOINT))
                .then()
                .extract()
                .response()
        expect:
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"))
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"))
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-13
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when configuration parameter SignatureLevel empty
     *
     * Expected Result: No Signature
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */

    @Description("")
    def "validateDetailedReportSignatureLevelEmptyValue"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
    }

    /**
     * TestCaseID: Detailed-Report-Signatures-14
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature when using pks11 to sign
     *
     * Expected Result: Signature exists
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    /*Testitud ja töötab RSA sertifikaatidega id-kaardiga. Ei tööta ECC kaardiga.
    Installida OpenSC
    slotIndex: 1 /Pin1 ja slotIndex: 2/Pin2*/

    @Ignore
    @Description("")
    def "validateDetailedReportSignatureLevelPkcs11"() {
        given:
        String filename = "hellopades-lt-sha256-rsa2048.pdf"
        Map request = detailedReportRequest(filename, VALID_SIGNATURE_POLICY_4)
        response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT)
    }

    private Response validateRequestForDetailedReport(Map requestBody, String validationUrl) {
        return given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().defaultContentCharset("UTF-8")))
                .body(requestBody)
                .when()
                .post(createUrl(validationUrl))
                .then()
                .extract()
                .response()
    }

    private Map detailedReportRequest(String fileName, String signaturePolicy) {
        [
                document: Base64.encodeBase64String(readFileFromTestResources(fileName)),
                filename: fileName,
                signaturePolicy: signaturePolicy,
                reportType: "Detailed"
        ]
    }

    protected byte[] readFileFromTestResources(String filename) {
        return readFileFromPath(TEST_FILE_BASE + getTestFilesDirectory() + filename)
    }

    protected static byte[] readFileFromPath(String pathName) {
        try {
            return Files.readAllBytes(FileSystems.getDefault().getPath(pathName))
        } catch (IOException e) {
            throw new RuntimeException(e)
        }
    }

    protected static String createXMLValidationRequestWithReportType(String base64Document, String filename, String reportType) {

        return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:ValidateDocument>\n" +
                "         <soap:ValidationRequest>\n" +
                "            <Document>" + base64Document + "</Document>\n" +
                "            <Filename>" + filename + "</Filename>\n" +
                "            <ReportType>" + reportType + "</ReportType>\n" +
                "         </soap:ValidationRequest>\n" +
                "      </soap:ValidateDocument>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>"
    }

    protected String validationRequestForDocumentReportType(String filename, String reportType) {
        return createXMLValidationRequestWithReportType(
                Base64.encodeBase64String(readFileFromTestResources(filename)),
                filename, reportType)
    }

    protected String getTestFilesDirectory() {
        return testFilesDirectory
    }

}
