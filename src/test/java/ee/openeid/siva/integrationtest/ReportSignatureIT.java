/*
 * Copyright 2017 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
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

package ee.openeid.siva.integrationtest;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.json.JSONObject;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@Tag("IntegrationTest")
@Disabled("SIVA-196") //Class disabled
public class ReportSignatureIT extends SiVaRestTests {

    private static final String TEST_FILES_DIRECTORY = "document_format_test_files/";
    private static final String VALIDATION_ENDPOINT = "/validate";

    @Override
    protected String getTestFilesDirectory() {
        return TEST_FILES_DIRECTORY;
    }

    /**
     * TestCaseID: Detailed-Report-Signature-1
     *
     * TestType: Auto
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Simple report signature should not be in response
     *
     * Expected Result: Simple report response should not contain signature
     *
     * File: hellopades-pades-lt-sha256-sign.pdf
     */
    @Test
    public void whenRequestingSimpleReport_thenValidationReportSignatureShouldNotBeInResponse() {
        post(validationRequestFor("hellopades-pades-lt-sha256-sign.pdf", null, "Simple"))
                .then()
                .body("validationReportSignature", emptyOrNullString());
    }

    /**
     * TestCaseID: Detailed-Report-Signature-2
     *
     * TestType: Auto
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Detailed report signature should be in response
     *
     * Expected Result: Detailed report response should contain signature
     *
     * File: hellopades-pades-lt-sha256-sign.pdf
     */
    @Test
    public void whenRequestingDetailedReport_thenValidationReportSignatureShouldBeInResponse() {
        post(validationRequestFor("hellopades-pades-lt-sha256-sign.pdf", null, "Detailed"))
                .then()
                .body("validationReportSignature", not(emptyOrNullString()));
    }

    /**
     * TestCaseID: Detailed-Report-Signature-3
     *
     * TestType: Auto
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: Validate detailed report signature
     *
     * Expected Result: Signed report is successfully validated
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Test
    public void validateDetailedReportSignature() {
        String filename = "hellopades-pades-lt-sha256-sign.pdf";
        String request = validationRequestFor(filename, VALID_SIGNATURE_POLICY_4, "Detailed");
        Response response = validateRequestForDetailedReport(request, VALIDATION_ENDPOINT);
        String validationReportSignature = response.jsonPath().getString("validationReportSignature");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("document", validationReportSignature);
        jsonObject.put("filename", "filename.pdf");
        Response reportSignatureValidation = given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(jsonObject.toString())
                .when()
                .post(VALIDATION_ENDPOINT)
                .then()
                .extract()
                .response();
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signaturesCount"), equalTo("1"));
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.validSignaturesCount"), equalTo("1"));
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo("XAdES_BASELINE_LT"));
        assertThat(reportSignatureValidation.jsonPath().getString("validationReport.validationConclusion.signatures.signatureFormat[0]"), equalTo("XAdES_BASELINE_LT"));
    }

    /**
     * TestCaseID: Detailed-Report-Signature-4
     *
     * TestType: Auto
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: In simple report reportSignatureEnabled parameter value true
     *
     * Expected Result: File hash in hex in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Test
    public void whenRequestingSimpleReport_andreportSignatureEnabledTrue_fileHash_InReport() {
        post(validationRequestFor("hellopades-pades-lt-sha256-sign.pdf", null, "Simple"))
                .then()
                .body("validationReport.validationConclusion.validatedDocument.fileHash", not(emptyOrNullString()));
    }

    /**
     * TestCaseID: Detailed-Report-Signature-5
     *
     * TestType: Auto
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface
     *
     * Title: In simple report reportSignatureEnabled parameter value false
     *
     * Expected Result: File hash in hex not in report
     *
     * File: hellopades-lt-sha256-rsa2048.pdf
     */
    @Disabled //This test should be ran manually after configuring the report signature feature
    @Test
    public void whenRequestingSimpleReport_andreportSignatureEnabledFalse_fileHash_NotInReport() {
        post(validationRequestFor("hellopades-pades-lt-sha256-sign.pdf", null, "Simple"))
                .then()
                .body("validationReport.validationConclusion.validatedDocument.fileHash", emptyOrNullString());
    }

    private Response validateRequestForDetailedReport(String request, String validationUrl) {
        return given()
                .contentType(ContentType.JSON)
                .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .body(request)
                .when()
                .post(validationUrl)
                .then()
                .extract()
                .response();
    }

} 
