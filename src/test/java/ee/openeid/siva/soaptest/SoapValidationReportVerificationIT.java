package ee.openeid.siva.soaptest;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import static ee.openeid.siva.common.DssMessages.QUAL_HAS_GRANTED_AT_ANS;
import static ee.openeid.siva.integrationtest.TestData.REPORT_TYPE_DETAILED;
import static ee.openeid.siva.integrationtest.TestData.SOAP_DETAILED_DATA_PREFIX;
import static ee.openeid.siva.integrationtest.TestData.SOAP_VALIDATION_CONCLUSION_PREFIX;
import static ee.openeid.siva.integrationtest.TestData.TOTAL_PASSED;

public class SoapValidationReportVerificationIT extends SiVaSoapTests {

    private static final String DEFAULT_TEST_FILES_DIRECTORY = "document_format_test_files/";

    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;


    /**
     * TestCaseID: Soap-ValidationSimpleReportVerification-1
     *
     * TestType: Automated
     *
     * Title: Filtering out warning "The trusted certificate does not match the trust service!" in Simple Report
     *
     * Expected Result: Warning "The trusted certificate does not match the trust service!" is not displayed in Simple Report
     *
     * File: validTsSignatureWithRolesAndProductionPlace.asice
     */
    @Test
    public void soapSimpleReportFilterTrustServiceWarning() {
        setTestFilesDirectory("bdoc/test/timestamp/");
        post(validationRequestForDocument("validTsSignatureWithRolesAndProductionPlace.asice"))
                .then().rootPath(SOAP_VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].Indication", Matchers.is(TOTAL_PASSED))
                .body("Signatures.Signature[0].Warnings", Matchers.emptyOrNullString());
    }

    /**
     * TestCaseID: Soap-ValidationSimpleReportVerification-2
     *
     * TestType: Automated
     *
     * Title: Filtering out warning "The certificate is not related to a granted status at time-stamp lowest POE time!" in Simple Report
     *
     * Expected Result: Error "The certificate is not related to a granted status at time-stamp lowest POE time!" is not present in Simple Report
     *
     * File: IB-4183_3.4kaart_RSA2047_TS.asice
     */
    @Test
    public void soapSimpleReportFilterLowestPoeTimeError() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDocument("IB-4183_3.4kaart_RSA2047_TS.asice"))
                .then().rootPath(SOAP_VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].Indication", Matchers.is(TOTAL_PASSED))
                .body("Signatures.Signature[0].Errors", Matchers.emptyOrNullString());
    }

    /**
     * TestCaseID: Soap-ValidationDetailedReportVerification-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Warning "The trusted certificate does not match the trust service!" in Detailed Report
     *
     * Expected Result: Warning "The trusted certificate does not match the trust service!" is not filtered out and is present in Detailed Report
     *
     * File: validTsSignatureWithRolesAndProductionPlace.asice
     */
    @Test
    public void soapDetailedReportTrustServiceWarningPresent() {
        setTestFilesDirectory("bdoc/test/timestamp/");
        post(validationRequestForDocumentReportType("validTsSignatureWithRolesAndProductionPlace.asice", REPORT_TYPE_DETAILED))
                .then().rootPath(SOAP_DETAILED_DATA_PREFIX + ".Signature.ValidationSignatureQualification.")
                .body("Conclusion.Warnings[0]", Matchers.equalTo("The trusted certificate does not match the trust service!"));
    }

    /**
     * TestCaseID: Soap-ValidationDetailedReportVerification-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Error "The certificate is not related to a granted status at time-stamp lowest POE time!" in Detailed Report
     *
     * Expected Result: Error "The certificate is not related to a granted status at time-stamp lowest POE time!" is displayed in Detailed Report and signature is TOTAL-PASSED
     *
     * File: IB-4183_3.4kaart_RSA2047_TS.asice
     */
    @Test
    public void soapDetailedReportLowestPoeTimeErrorPresent() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDocumentReportType("IB-4183_3.4kaart_RSA2047_TS.asice", REPORT_TYPE_DETAILED))
                .then().rootPath(SOAP_DETAILED_DATA_PREFIX + ".Signature.")
                .body("Conclusion.Indication", Matchers.equalTo("TOTAL_PASSED"))
                .body("Timestamp.ValidationTimestampQualification.Conclusion.Errors", Matchers.equalTo(QUAL_HAS_GRANTED_AT_ANS.getValue()));
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
}
