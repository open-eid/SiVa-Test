/*
 * Copyright 2018 - 2024 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.soaptest;

import ee.openeid.siva.common.DateTimeMatcher;
import ee.openeid.siva.integrationtest.TestData;
import ee.openeid.siva.validation.Datafile;
import ee.openeid.siva.validation.JSONHashcodeValidationRequest;
import ee.openeid.siva.validation.PredefinedValidationPolicySource;
import ee.openeid.siva.validation.ReportType;
import ee.openeid.siva.validation.SignatureFile;
import ee.openeid.siva.validation.ValidationPolicy;
import io.restassured.response.ValidatableResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static ee.openeid.siva.integrationtest.TestData.HASH_ALGO_SHA256;
import static ee.openeid.siva.integrationtest.TestData.HASH_ALGO_SHA512;
import static ee.openeid.siva.integrationtest.TestData.INDETERMINATE;
import static ee.openeid.siva.integrationtest.TestData.MOCK_XADES_DATAFILE_FILENAME;
import static ee.openeid.siva.integrationtest.TestData.REFERENCE_DATA_NOT_FOUND;
import static ee.openeid.siva.integrationtest.TestData.REFERENCE_DATA_NOT_INTACT;
import static ee.openeid.siva.integrationtest.TestData.SIGNATURE_LEVEL_INDETERMINATE_QESIG;
import static ee.openeid.siva.integrationtest.TestData.SIGNATURE_POLICY_1;
import static ee.openeid.siva.integrationtest.TestData.SIGNATURE_POLICY_2;
import static ee.openeid.siva.integrationtest.TestData.SIGNATURE_SCOPE_DIGEST;
import static ee.openeid.siva.integrationtest.TestData.SUB_INDICATION_SIGNED_DATA_NOT_FOUND;
import static ee.openeid.siva.integrationtest.TestData.TOTAL_FAILED;
import static ee.openeid.siva.integrationtest.TestData.VALID_SIGNATURE_SCOPE_CONTENT_DIGEST;
import static ee.openeid.siva.integrationtest.TestData.VALID_SIGNATURE_SCOPE_CONTENT_FULL;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.oneOf;

@Tag("IntegrationTest")
public class SoapHashcodeValidationRequestIT extends SiVaSoapTests {

    private static final String DEFAULT_TEST_FILES_DIRECTORY = "xades/";
    private static final String VALIDATION_CONCLUSION_PREFIX = "Envelope.Body.HashcodeValidationResponse.ValidationReport.ValidationConclusion.";
    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;
    private ZonedDateTime testStartDate;

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
        testStartDate = ZonedDateTime.now(ZoneId.of("GMT"));
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Valid request
     *
     * Expected Result: Simple report is returned with valid signatures
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void okHashcodeValidationWithSimpleReport() {
        JSONHashcodeValidationRequest request = validRequestBody();
        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Valid request with detailed report
     *
     * Expected Result: Simple report is returned with valid signatures
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void okHashcodeValidationDetailedReportRequested() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setReportType(ReportType.DETAILED);
        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Report type missing
     *
     * Expected Result: Default is used
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void reportTypeMissingDefaultsToSimple() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setReportType(null);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Report type case sensitivity
     *
     * Expected Result: Report type is case insensitive
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void reportTypeCaseInsensitive() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setReportType("SiMpLe");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Report type is invalid
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void reportTypeInvalid() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setReportType("INVALID_REPORT_TYPE");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-enumeration-valid: Value 'INVALID_REPORT_TYPE' is not facet-valid with respect to enumeration '[SIMPLE, DETAILED, DIAGNOSTIC]'. It must be a value from the enumeration. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Report-Type-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Valid request with report Diagnostic
     *
     * Expected Result: Simple report is returned with valid signatures
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void okHashcodeValidationDiagnosticReportRequested() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setReportType(ReportType.DIAGNOSTIC);
        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature policy POLv3
     *
     * Expected Result: Correct policy is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyPOLv3() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy(SIGNATURE_POLICY_1);

        ValidatableResponse response = postHashcodeValidation(request)
                .then()
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyName", equalTo(SIGNATURE_POLICY_1));

        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature policy POLv4
     *
     * Expected Result: Correct policy is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyPOLv4() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy(SIGNATURE_POLICY_2);

        ValidatableResponse response = postHashcodeValidation(request)
                .then()
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyName", equalTo(SIGNATURE_POLICY_2));

        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Default policy
     *
     * Expected Result: POLv4 is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyMissing_defaultsToPOLv4() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy(null);

        ValidatableResponse response = postHashcodeValidation(request).then()
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyName", equalTo(SIGNATURE_POLICY_2));

        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Invalid policy asked
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyInvalid() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy("POLv2");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Invalid signature policy: " + request.getSignaturePolicy() + "; Available abstractPolicies: [POLv3, POLv4]");
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Invalid policy format
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyInvalidFormat() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy("POLv2.*");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-pattern-valid: Value 'POLv2.*' is not facet-valid with respect to pattern '[A-Za-z0-9_ -]*' for type 'SignaturePolicy'. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-Validation-Policy-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Too long policy
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void signaturePolicyTooLong() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignaturePolicy(StringUtils.repeat('a', 101));

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-maxLength-valid: Value 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' with length = '101' is not facet-valid with respect to maxLength '100' for type 'SignaturePolicy'. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Signature-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature file missing
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void signatureFilesMissing() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignatureFiles(null);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response, "Unmarshalling Error: cvc-complex-type.2.4.a: Invalid content was found starting with element 'ReportType'. One of '{SignatureFiles}' is expected. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Signature-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature file empty
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void signatureFilesEmpty() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.setSignatureFiles(new ArrayList<>());

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response, "Unmarshalling Error: cvc-complex-type.2.4.b: The content of element 'SignatureFiles' is not complete. One of '{SignatureFile}' is expected. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Signature-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature file not Base64
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void signatureNotBase64Encoded() {
        JSONHashcodeValidationRequest request = validRequestBody();

        request.getSignatureFiles().get(0).setSignature("NOT.BASE64.ENCODED.VALUE");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response, SIGNATURE_FILE_NOT_BASE64_ENCODED);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Signature-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature file without signature
     *
     * Expected Result: Report without signature is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void signatureContentWithoutSignature() {
        String randomXmlFileWithoutSignature = "PD94bWwgdmVyc2lvbj0nMS4wJyAgZW5jb2Rpbmc9J1VURi04JyA/Pg0KPHRlc3Q+DQoJPGRhdGE+DQoJCTxzb21ldGhpbmc+c29tZSBkYXRhPC9zb21ldGhpbmc+DQoJPC9kYXRhPg0KPC90ZXN0Pg0K";
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).setSignature(randomXmlFileWithoutSignature);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithoutSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Signature-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Signature file not XML
     *
     * Expected Result: Report without signature is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void signatureContentNotXML() {
        String notXmlFormattedContent = Base64.encodeBase64String("NOT_XML_FORMATTED_FILE_CONTENT".getBytes(StandardCharsets.UTF_8));
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).setSignature(notXmlFormattedContent);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response, SIGNATURE_FILE_MALFORMED);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request without datafiles
     *
     * Expected Result: Validation report is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFilesMissing() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).setDatafiles(null);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with empty data files
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFilesEmpty() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).setDatafiles(new ArrayList<>());

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-complex-type.2.4.b: The content of element 'DataFiles' is not complete. One of '{DataFile}' is expected. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request without datafile filename
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileFilenameMissing() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setFilename(null);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-complex-type.2.4.a: Invalid content was found starting with element 'HashAlgo'. One of '{Filename}' is expected. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with empty filename
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileFilenameEmpty() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setFilename("");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Invalid datafile filename format");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request without datafile filename
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileFilenameEmptyWhitespace() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setFilename(" ");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Invalid datafile filename format");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with too long datafile name
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileFilenameTooLong() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setFilename(StringUtils.repeat('a', 261));

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-maxLength-valid: Value 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' with length = '261' is not facet-valid with respect to maxLength '260' for type 'Filename'. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-7
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with invalid hash algorithm
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashAlgorithmInvalid() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHashAlgo("INVALID_HASH_ALGORITHM");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-enumeration-valid: Value 'INVALID_HASH_ALGORITHM' is not facet-valid with respect to enumeration '[SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160, MD2, MD5]'. It must be a value from the enumeration. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-8
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Hash algo small case
     *
     * Expected Result: Report is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashAlgorithmCaseInsensitive() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHashAlgo("sha256");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-9
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Hash algo mismatch
     *
     * Expected Result: Report with invalid signature
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashAlgorithmDoesNotMatchWithSignatureDataFileHashAlgorithm() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHashAlgo(HASH_ALGO_SHA512);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertValidationConclusion(response, request);
        assertSignatureHashFailure(response, SUB_INDICATION_SIGNED_DATA_NOT_FOUND, SIGNATURE_LEVEL_INDETERMINATE_QESIG, INDETERMINATE);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-10
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Datafile hash missing
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashMissing() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHash(null);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-complex-type.2.4.b: The content of element 'DataFile' is not complete. One of '{Hash}' is expected. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-11
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Data file hash empty
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashEmpty() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHash("");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response,
                "Unmarshalling Error: cvc-pattern-valid: Value '' is not facet-valid with respect to pattern '\\S+' for type 'NotEmptyString'. ");
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-Datafile-12
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Datafile hash not Base64
     *
     * Expected Result: Error is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashNotBase64Encoded() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHash("NOT.BASE64.ENCODED.VALUE");

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertClientFault(response, INVALID_BASE_64);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Multiple data files
     *
     * Expected Result: Report is returned with signature statuses
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void multipleDataFiles_firstDataFileIncorrect_secondDataFileCorrect() {
        JSONHashcodeValidationRequest request = validRequestBody();

        Datafile invalidDataFile = new Datafile();
        invalidDataFile.setHash(Base64.encodeBase64String("INVALID_SIGNATURE_DIGEST".getBytes(StandardCharsets.UTF_8)));
        invalidDataFile.setHashAlgo(TestData.MOCK_XADES_DATAFILE_HASH_ALGO);
        invalidDataFile.setFilename("INVALID_FILE");

        Datafile validDataFile = new Datafile();
        validDataFile.setHash(TestData.MOCK_XADES_DATAFILE_HASH);
        validDataFile.setHashAlgo(TestData.MOCK_XADES_DATAFILE_HASH_ALGO);
        validDataFile.setFilename(MOCK_XADES_DATAFILE_FILENAME);

        request.getSignatureFiles().get(0).setDatafiles(Arrays.asList(
                invalidDataFile,
                validDataFile)
        );

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertSimpleReportWithSignature(response, request);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Wrong hash
     *
     * Expected Result: Report is returned with invalid signature
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashDoesNotMatchWithSignatureFile_totalFailedHashFailure() {
        JSONHashcodeValidationRequest request = validRequestBody();
        request.getSignatureFiles().get(0).getDatafiles().get(0).setHash(Base64.encodeBase64String("INVALID_SIGNATURE_DIGEST".getBytes(StandardCharsets.UTF_8)));

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertValidationConclusion(response, request);
        assertSignatureHashFailure(response, TestData.SUB_INDICATION_HASH_FAILURE, TestData.SIGNATURE_LEVEL_NOT_ADES_QC_QSCD, TOTAL_FAILED);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Wrong data file name
     *
     * Expected Result: Report is returned with signature statuses
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void dataFileHashCorrectButFilenameDoesNotMatchWithSignatureFile() {
        JSONHashcodeValidationRequest request = validRequestBody();
        String filename = "INVALID_FILE_NAME.pdf";
        request.getSignatureFiles().get(0).getDatafiles().get(0).setFilename(filename);

        ValidatableResponse response = postHashcodeValidation(request).then();
        assertValidationConclusion(response, request);
        assertSignatureDataNotFound(filename, response);
    }

    /**
     * TestCaseID: Soap-Hashcode-ValidationRequest-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Empty request body
     *
     * Expected Result: Report is returned with signature statuses
     *
     * File: Valid_XAdES_LT_TS.xml
     */
    @Test
    public void validationRequestBodyEmpty() {
        String emptyRequestBody =
                "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                        "   <soapenv:Header/>\n" +
                        "   <soapenv:Body>\n" +
                        "   </soapenv:Body>\n" +
                        "</soapenv:Envelope>";
        postHashcodeValidation(emptyRequestBody)
                .then()
                .statusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR)
                .body("Envelope.Body.Fault.faultcode", is(SERVER_FAULT))
                .body("Envelope.Body.Fault.faultstring", is("No binding operation info while invoking unknown method with params unknown."));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Special-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Datafile has + in name
     *
     * Expected Result: The document should pass the validation
     *
     * File: test+document.xml
     */
    @Test
    public void validXadesWithPlusInDataFileName() {
        postHashcodeValidation(createXMLHashcodeValidationRequestSimple("test+document.xml"))
                .then()
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].SignatureFormat", is("XAdES_BASELINE_LT"))
                .body("Signatures.Signature[0].Indication", is("TOTAL-PASSED"))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is("2019-02-05T12:43:15Z"))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is("test+document.txt"))
                .body("ValidSignaturesCount", is("1"));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Special-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Datafile has space in name
     *
     * Expected Result: The document should pass the validation
     *
     * File: spacesInDatafile.xml
     */
    @Test
    public void validXadesWithSpaceInDataFileName() {
        postHashcodeValidation(createXMLHashcodeValidationRequestSimple("spacesInDatafile.xml"))
                .then()
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].SignatureFormat", is("XAdES_BASELINE_LT"))
                .body("Signatures.Signature[0].Indication", is("TOTAL-PASSED"))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is("2019-02-05T13:22:04Z"))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is("Te st in g.txt"))
                .body("ValidSignaturesCount", is("1"));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Special-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Datafile has + in name with full API request
     *
     * Expected Result: The document should pass the validation
     *
     * File: test+document.xml
     */
    @Test
    public void datafileWithPlusInFilenameRequestedThrougApi() {
        postHashcodeValidation(createXMLHashcodeValidationRequest(validRequestBody("test+document.xml", HASH_ALGO_SHA256, "test+document.txt", "heKN3NGQ0HttzgmfKG0L243dfG7W+6kTMO5n7YbKeS4=")))
                .then()
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].SignatureFormat", is("XAdES_BASELINE_LT"))
                .body("Signatures.Signature[0].Indication", is("TOTAL-PASSED"))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is("2019-02-05T12:43:15Z"))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is("test+document.txt"))
                .body("ValidSignaturesCount", is("1"));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Special-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Datafile has space in name with full API request
     *
     * Expected Result: The document should pass the validation
     *
     * File: spacesInDatafile.xml
     */
    @Test
    public void datafileWithSpaceInFilenameRequestedThroughApi() {
        postHashcodeValidation(createXMLHashcodeValidationRequest(validRequestBody("spacesInDatafile.xml", HASH_ALGO_SHA256, "Te st in g.txt", "5UxI8Rm1jUZm48+Vkdutyrsyr3L/MPu/RK1V81AeKEY=")))
                .then()
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.Signature[0].SignatureFormat", is("XAdES_BASELINE_LT"))
                .body("Signatures.Signature[0].Indication", is("TOTAL-PASSED"))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is("2019-02-05T13:22:04Z"))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is("Te st in g.txt"))
                .body("ValidSignaturesCount", is("1"));
    }

    private void assertSimpleReportWithSignature(ValidatableResponse response, JSONHashcodeValidationRequest request) {
        assertValidationConclusion(response, request);
        assertSignatureTotalPassed(response);
    }

    private void assertSimpleReportWithoutSignature(ValidatableResponse response, JSONHashcodeValidationRequest request) {
        assertValidationConclusion(response, request);
        response
                .body(VALIDATION_CONCLUSION_PREFIX + "Signatures", emptyOrNullString())
                .body(VALIDATION_CONCLUSION_PREFIX + "ValidSignaturesCount", is("0"))
                .body(VALIDATION_CONCLUSION_PREFIX + "SignaturesCount", is("0"));
    }

    private void assertValidationConclusion(ValidatableResponse response, JSONHashcodeValidationRequest request) {
        response.statusCode(HttpStatus.SC_OK)
                .body(VALIDATION_CONCLUSION_PREFIX + "ValidationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body(VALIDATION_CONCLUSION_PREFIX + "ValidationLevel", is(TestData.VALIDATION_LEVEL_ARCHIVAL_DATA));

        ValidationPolicy signaturePolicy;
        if (request.getSignaturePolicy() == null) {
            signaturePolicy = determineValidationPolicy(SIGNATURE_POLICY_2);
        } else {
            signaturePolicy = determineValidationPolicy(request.getSignaturePolicy());
        }

        response
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyDescription", equalTo(signaturePolicy.getDescription()))
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyName", equalTo(signaturePolicy.getName()))
                .body(VALIDATION_CONCLUSION_PREFIX + "Policy.PolicyUrl", equalTo(signaturePolicy.getUrl()));
    }

    private ValidationPolicy determineValidationPolicy(String signaturePolicy) {
        if (SIGNATURE_POLICY_1.equals(signaturePolicy)) {
            return PredefinedValidationPolicySource.ADES_POLICY;
        } else if (SIGNATURE_POLICY_2.equals(signaturePolicy)) {
            return PredefinedValidationPolicySource.QES_POLICY;
        } else {
            throw new IllegalArgumentException("Unknown validation policy '" + signaturePolicy + "'");
        }
    }

    private void assertSignatureTotalPassed(ValidatableResponse response) {
        response.rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.children().size()", is(1))
                .body("Signatures.Signature[0].Id", is(TestData.MOCK_XADES_SIGNATURE_ID))
                .body("Signatures.Signature[0].SignatureFormat", is(TestData.SIGNATURE_FORMAT_XADES_LT))
                .body("Signatures.Signature[0].SignatureLevel", is(TestData.SIGNATURE_LEVEL_QESIG))
                .body("Signatures.Signature[0].SignedBy", is(TestData.MOCK_XADES_SIGNATURE_SIGNER))
                .body("Signatures.Signature[0].Indication", is(TestData.TOTAL_PASSED))
                .body("Signatures.Signature[0].SignatureScopes.children().size()", is(1))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is(MOCK_XADES_DATAFILE_FILENAME))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Scope", is(SIGNATURE_SCOPE_DIGEST))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Content", is(VALID_SIGNATURE_SCOPE_CONTENT_DIGEST))
                .body("Signatures.Signature[0].ClaimedSigningTime", is(TestData.MOCK_XADES_SIGNATURE_CLAIMED_SIGNING_TIME))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is(TestData.MOCK_XADES_SIGNATURE_BEST_SIGNATURE_TIME))
                .body("Signatures.Signature[0].Errors", emptyOrNullString())
                .body("ValidSignaturesCount", is("1"))
                .body("SignaturesCount", is("1"));
    }

    private void assertSignatureDataNotFound(String datafileName, ValidatableResponse response) {
        response.rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.children().size()", is(1))
                .body("Signatures.Signature[0].Id", is(TestData.MOCK_XADES_SIGNATURE_ID))
                .body("Signatures.Signature[0].SignatureFormat", is(TestData.SIGNATURE_FORMAT_XADES_LT))
                .body("Signatures.Signature[0].SignatureLevel", is(SIGNATURE_LEVEL_INDETERMINATE_QESIG))
                .body("Signatures.Signature[0].SignedBy", is(TestData.MOCK_XADES_SIGNATURE_SIGNER))
                .body("Signatures.Signature[0].Indication", is(INDETERMINATE))
                .body("Signatures.Signature[0].SubIndication", is(SUB_INDICATION_SIGNED_DATA_NOT_FOUND))
                .body("Signatures.Signature[0].SignatureScopes.children().size()", is(1))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is(MOCK_XADES_DATAFILE_FILENAME))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Scope", is(TestData.SIGNATURE_SCOPE_FULL))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Content", is(VALID_SIGNATURE_SCOPE_CONTENT_FULL))
                .body("Signatures.Signature[0].ClaimedSigningTime", is(TestData.MOCK_XADES_SIGNATURE_CLAIMED_SIGNING_TIME))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is(TestData.MOCK_XADES_SIGNATURE_BEST_SIGNATURE_TIME))
                .body("Signatures.Signature[0].Errors.children().size()", greaterThanOrEqualTo(1))
                .body("Signatures.Signature[0].Errors.Error.Content", hasItem(REFERENCE_DATA_NOT_FOUND))
                .body("ValidSignaturesCount", is("0"))
                .body("SignaturesCount", is("1"));
    }

    private void assertSignatureHashFailure(ValidatableResponse response, String subIndication, String signatureLevel, String indication) {
        response.rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("Signatures.children().size()", is(1))
                .body("Signatures.Signature[0].Id", is(TestData.MOCK_XADES_SIGNATURE_ID))
                .body("Signatures.Signature[0].SignatureFormat", is(TestData.SIGNATURE_FORMAT_XADES_LT))
                .body("Signatures.Signature[0].SignatureLevel", is(signatureLevel))
                .body("Signatures.Signature[0].SignedBy", is(TestData.MOCK_XADES_SIGNATURE_SIGNER))
                .body("Signatures.Signature[0].Indication", is(indication))
                .body("Signatures.Signature[0].SubIndication", is(subIndication))
                .body("Signatures.Signature[0].SignatureScopes.children().size()", is(1))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Name", is(MOCK_XADES_DATAFILE_FILENAME))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Scope", is(TestData.SIGNATURE_SCOPE_FULL))
                .body("Signatures.Signature[0].SignatureScopes.SignatureScope[0].Content", is(VALID_SIGNATURE_SCOPE_CONTENT_FULL))
                .body("Signatures.Signature[0].ClaimedSigningTime", is(TestData.MOCK_XADES_SIGNATURE_CLAIMED_SIGNING_TIME))
                .body("Signatures.Signature[0].Info.BestSignatureTime", is(TestData.MOCK_XADES_SIGNATURE_BEST_SIGNATURE_TIME))
                .body("Signatures.Signature[0].Errors.children().size()", greaterThanOrEqualTo(1))
                .body("Signatures.Signature[0].Errors.Error.Content", hasItem(oneOf(REFERENCE_DATA_NOT_INTACT, REFERENCE_DATA_NOT_FOUND)))
                .body("ValidSignaturesCount", is("0"))
                .body("SignaturesCount", is("1"));
    }

    private void assertClientFault(ValidatableResponse response, String errorMessage) {
        response
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", equalTo(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring", equalTo(errorMessage));
    }

    private JSONHashcodeValidationRequest validRequestBody() {
        JSONHashcodeValidationRequest request = new JSONHashcodeValidationRequest();

        Datafile datafile = new Datafile();
        datafile.setHash(TestData.MOCK_XADES_DATAFILE_HASH);
        datafile.setHashAlgo(TestData.MOCK_XADES_DATAFILE_HASH_ALGO);
        datafile.setFilename(MOCK_XADES_DATAFILE_FILENAME);

        request.setReportType(ReportType.SIMPLE);
        request.setSignaturePolicy(SIGNATURE_POLICY_1);
        SignatureFile signatureFile = new SignatureFile();
        signatureFile.setDatafiles(Collections.singletonList(datafile));
        signatureFile.setSignature(Base64.encodeBase64String(readFileFromTestResources(TestData.MOCK_XADES_SIGNATURE_FILE)));
        request.setSignatureFiles(Collections.singletonList(signatureFile));

        return request;
    }

    private JSONHashcodeValidationRequest validRequestBody(String signatureFileName, String hashAlgo, String datafileName, String datafileHash) {
        JSONHashcodeValidationRequest request = new JSONHashcodeValidationRequest();

        Datafile datafile = new Datafile();
        datafile.setHash(datafileHash);
        datafile.setHashAlgo(hashAlgo);
        datafile.setFilename(datafileName);

        request.setReportType(ReportType.SIMPLE);
        request.setSignaturePolicy(SIGNATURE_POLICY_1);
        SignatureFile signatureFile = new SignatureFile();
        signatureFile.setDatafiles(Collections.singletonList(datafile));
        signatureFile.setSignature(Base64.encodeBase64String(readFileFromTestResources(signatureFileName)));
        request.setSignatureFiles(Collections.singletonList(signatureFile));

        return request;
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
}
