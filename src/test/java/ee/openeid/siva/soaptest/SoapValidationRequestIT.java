/*
 * Copyright 2020 - 2024 Riigi Infosüsteemi Amet
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

import io.restassured.response.ValidatableResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static ee.openeid.siva.integrationtest.TestData.*;
import static org.hamcrest.Matchers.*;

@Tag("IntegrationTest")
public class SoapValidationRequestIT extends SiVaSoapTests {

    private static final String DEFAULT_TEST_FILES_DIRECTORY = "document_format_test_files/";
    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Empty request body
     *
     * Expected Result: Error is returned stating mismatch with required elements
     *
     * File: not relevant
     */
    @Test
    public void soapValidationRequestEmptyInputs() {
        post(validationRequestForDocumentExtended("", "", "", ""))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_NOT_BASE64));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with not base64 string as document
     *
     * Expected Result: Error is returned stating encoding problem
     *
     * File: not relevant
     */
    @Test
    public void soapValidationRequestNonBase64Input() {
        String encodedString = ",:";
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.ddoc", "DDOC", VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_NOT_BASE64));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Verification of wrong document type as input
     *
     * Expected Result: Correct error code is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestDocumentTypeShouldReturnError() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", "XROAD", VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_TYPE_NOT_ACCEPTED));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request has long filename field
     *
     * Expected Result: Report is returned with the same filename
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestLongFilename() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String filename = StringUtils.repeat("a", 250) + ".bdoc";
        post(validationRequestForDocumentExtended(encodedString, filename, null, VALID_SIGNATURE_POLICY_4))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidatedDocument.Filename", Matchers.is(filename));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-7
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Totally empty request body is sent
     *
     * Expected Result: Error is given
     *
     * File: not relevant
     */
    @Test
    public void soapValidationRequestEmptyBody() {
        String emptyRequestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        post(emptyRequestBody)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_NOT_BASE64));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-8
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with more parameters than expected is sent
     *
     * Expected Result: Error is given or extra parameters are ignored?
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestExtraKeyBetweenValues() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String requestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:ValidateDocument>\n" +
                "         <soap:ValidationRequest>\n" +
                "            <Document>" + encodedString + "</Document>\n" +
                "            <Filename>Valid_IDCard_MobID_signatures.bdoc</Filename>\n" +
                "            <DocumentVersion>V1.3</DocumentVersion>\n" +
                "         </soap:ValidationRequest>\n" +
                "      </soap:ValidateDocument>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        post(requestBody)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.startsWith("Unmarshalling Error: cvc-complex-type.2.4.a: Invalid content was found starting with element 'DocumentVersion'. One of '{ReportType, DocumentType, SignaturePolicy}' is expected. "));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-9
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with more parameters than expected is sent
     *
     * Expected Result: Error is given or extra parameters are ignored?
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestExtraKeyAtTheEnd() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String requestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:ValidateDocument>\n" +
                "         <soap:ValidationRequest>\n" +
                "            <Document>" + encodedString + "</Document>\n" +
                "            <Filename>Valid_IDCard_MobID_signatures.bdoc</Filename>\n" +
                "            <SignaturePolicy>" + VALID_SIGNATURE_POLICY_3 + "</SignaturePolicy>\n" +
                "            <DocumentVersion>V1.3</DocumentVersion>\n" +
                "         </soap:ValidationRequest>\n" +
                "      </soap:ValidateDocument>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        post(requestBody)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.startsWith("Unmarshalling Error: cvc-complex-type.2.4.d: Invalid content was found starting with element 'DocumentVersion'. No child element is expected at this point."));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-10
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with special chars is sent
     *
     * Expected Result: Validation report is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestUnusualChars() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "ÕValid_IDCard_MobID_signatures.bdocÄÖÜ", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidatedDocument.Filename", Matchers.is("ÕValid_IDCard_MobID_signatures.bdocÄÖÜ"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-11
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with no optional SignaturePolicy field
     *
     * Expected Result: Validation report is returned using default policy
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestNoPolicyKey() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String requestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:ValidateDocument>\n" +
                "         <soap:ValidationRequest>\n" +
                "            <Document>" + encodedString + "</Document>\n" +
                "            <Filename>Valid_IDCard_MobID_signatures.bdoc</Filename>\n" +
                "         </soap:ValidationRequest>\n" +
                "      </soap:ValidateDocument>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        post(requestBody)
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidSignaturesCount", Matchers.is("2"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-12
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with XML expansion
     *
     * Expected Result: Error is returned and Entity is not handled
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestWithXmlExpansionAttack() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String requestBody =
                "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                        "<!ENTITY lol \"lol\">\n" +
                        "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
                        "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
                        "<!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n" +
                        "<!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n" +
                        "<!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n" +
                        "<!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">\n" +
                        "<!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">\n" +
                        "<!ENTITY xxe \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n" +
                        "]>" +
                        "   <soapenv:Header/>\n" +
                        "   <soapenv:Body>\n" +
                        "      <soap:ValidateDocument>\n" +
                        "         <soap:ValidationRequest>\n" +
                        "            <Document>" + encodedString + "</Document>\n" +
                        "            <Filename>&xxe</Filename>\n" +
                        "         </soap:ValidationRequest>\n" +
                        "      </soap:ValidateDocument>\n" +
                        "   </soapenv:Body>\n" +
                        "</soapenv:Envelope>";
        post(requestBody)
                .then()
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is("soap:Client"))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.containsString("Error reading XMLStreamReader: Unrecognized XML directive; expected CDATA or comment"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-13
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request XML external entity attack
     *
     * Expected Result: Error message is returned and Doctype field is not handled
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestXmlEntityAttack() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String requestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "<!DOCTYPE SignaturePolicy PUBLIC \"-//VSR//PENTEST//EN\" \"http://localhost:1234/\">" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:ValidateDocument>\n" +
                "         <soap:ValidationRequest>\n" +
                "            <Document>" + encodedString + "</Document>\n" +
                "            <Filename>Valid_IDCard_MobID_signatures.bdoc</Filename>\n" +
                "            <SigmaturePolicy>" + "" + "</SignaturePolicy>" +
                "         </soap:ValidationRequest>\n" +
                "      </soap:ValidateDocument>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        post(requestBody)
                .then()
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is("soap:Client"))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.containsString("Error reading XMLStreamReader: Unrecognized XML directive; expected CDATA or comment"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-14
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with empty document
     *
     * Expected Result: Error is returned
     *
     * File: not relevant
     */
    @Test
    public void soapValidationRequestWithEmptyDocument() {
        post(validationRequestForDocumentExtended("", "Valid_IDCard_MobID_signatures.bdoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_NOT_BASE64));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-15
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with empty filename
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestWithEmptyFilename() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_FILENAME));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-16
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with not allowed signature policy characters
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationWithNotAllowedSignaturePolicyContent() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", null, "/"))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_SIGNATURE_POLICY));
    }


    /**
     * TestCaseID: Soap-ValidationRequest-17
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Request with wrong signature policy
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestWrongSignaturePolicy() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", null, INVALID_SIGNATURE_POLICY))
                .then()
                .rootPath(SOAP_ERROR_RESPONSE_PREFIX)
                .statusCode(HttpStatus.SC_OK)
                .body("faultcode", Matchers.is(CLIENT_FAULT))
                .body("faultstring", Matchers.is("Invalid signature policy: " + INVALID_SIGNATURE_POLICY + "; Available abstractPolicies: [" + VALID_SIGNATURE_POLICY_3 + ", " + VALID_SIGNATURE_POLICY_4 + "]"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-18
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: SignaturePolicy is over allowed length
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestTooLongSignaturePolicy() {
        String filename = "Valid_IDCard_MobID_signatures.bdoc";
        String encodedString = Base64.encodeBase64String(readFileFromTestResources(filename));
        String signaturePolicy = StringUtils.repeat("a", 101);
        String request = validationRequestForDocumentExtended(encodedString, filename, null, signaturePolicy);
        post(request)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_SIGNATURE_POLICY));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-19
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: SignaturePolicy is under allowed length
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestTooShortSignaturePolicy() {
        String filename = "Valid_IDCard_MobID_signatures.bdoc";
        String encodedString = Base64.encodeBase64String(readFileFromTestResources(filename));
        String signaturePolicy = "";
        String request = validationRequestForDocumentExtended(encodedString, filename, null, signaturePolicy);
        post(request)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_SIGNATURE_POLICY));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-20
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Filename is under allowed length
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestTooShortFilename() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String filename = "";
        String request = validationRequestForDocumentExtended(encodedString, filename, null, VALID_SIGNATURE_POLICY_3);
        post(request)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_FILENAME));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-21
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Filename is over allowed length
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestTooLongFilename() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        String filename = StringUtils.repeat("a", 261) + ".bdoc";
        String request = validationRequestForDocumentExtended(encodedString, filename, null, VALID_SIGNATURE_POLICY_3);
        post(request)
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(INVALID_FILENAME));
    }

    /**
     * TestCaseID: Soap-BdocValidationRequest-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Input random base64 string as document with bdoc document type
     *
     * Expected Result: Error is returned stating problem in document
     *
     * File: not relevant
     */
    @Test
    public void validationRequestRandomInputAsBdocDocument() {
        String encodedString = "ZCxTgQxDET7/lNizNZ4hrB1Ug8I0kKpVDkHEgWqNjcKFMD89LsIpdCkpUEsFBgAAAAAFAAUAPgIAAEM3AAAAAA==";
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-BdocValidationRequest-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Verification of filename value (filename do not match the actual file)
     *
     * Expected Result: The same filename is returned as sent in the request
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapValidationRequestWrongFilename() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "TotallyRandomFilename.exe", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidatedDocument.Filename", Matchers.is("TotallyRandomFilename.exe"));
    }

    /**
     * TestCaseID: Soap-BdocValidationRequest-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Mismatch in documentType and actual document (bdoc and pdf)
     *
     * Expected Result: Error is returned
     *
     * File: PdfValidSingleSignature.pdf
     */
    @Test
    public void soapBdocValidationRequestNotMatchingDocumentTypeAndActualFilePdf() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("PdfValidSingleSignature.pdf"));
        post(validationRequestForDocumentExtended(encodedString, "PdfValidSingleSignature.bdoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-BdocValidationRequest-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Bdoc file, not existing value in signaturePolicy
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapBdocValidationRequestWrongSignaturePolicy() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", null, INVALID_SIGNATURE_POLICY))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.containsString("Invalid signature policy: " + INVALID_SIGNATURE_POLICY + "; Available abstractPolicies: [" + VALID_SIGNATURE_POLICY_3 + ", " + VALID_SIGNATURE_POLICY_4 + "]"));
    }

    /**
     * TestCaseID: Soap-BdocValidationRequest-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Bdoc file, policy fiels should be case insensitive
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapBdocValidationRequestCaseInsensitivePolicy() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.bdoc", null, SMALL_CASE_VALID_SIGNATURE_POLICY_3))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidSignaturesCount", Matchers.is("2"));
    }

     /**
     * TestCaseID: Soap-DdocValidationRequest-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Input random base64 string as document with ddoc document type
     *
     * Expected Result: Error is returned stating problem in document
     *
     * File:
     */
    @Test
    public void validationRequestRandomInputAsDdocDocument() {
        String encodedString = "ZCxTgQxDET7/lNizNZ4hrB1Ug8I0kKpVDkHEgWqNjcKFMD89LsIpdCkpUEsFBgAAAAAFAAUAPgIAAEM3AAAAAA==";
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.ddoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-DdocValidationRequest-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Mismatch in documentType and actual document (ddoc and bdoc)
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void validationRequestNotMatchingDocumentTypeAndActualFileDdocBdoc() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.ddoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-DdocValidationRequest-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Mismatch in documentType and actual document (ddoc and bdoc)
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void soapDdocValidationRequestNotMatchingDocumentTypeAndActualFileBdoc() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.ddoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-DdocValidationRequest-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Mismatch in documentType and actual document (ddoc and pdf)
     *
     * Expected Result: Error is returned
     *
     * File: PdfValidSingleSignature.pdf
     */
    @Test
    public void soapDdocValidationRequestNotMatchingDocumentTypeAndActualFilePdf() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("PdfValidSingleSignature.pdf"));
        post(validationRequestForDocumentExtended(encodedString, "PdfValidSingleSignature.ddoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-DdocValidationRequest-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Ddoc file, not existing value in signaturePolicy
     *
     * Expected Result: Error is returned
     *
     * File: igasugust1.3.ddoc
     */
    @Test
    public void soapDdocValidationRequestWrongSignaturePolicy() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("igasugust1.3.ddoc"));
        post(validationRequestForDocumentExtended(encodedString, "igasugust1.3.ddoc", null, INVALID_SIGNATURE_POLICY))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is("Invalid signature policy: " + INVALID_SIGNATURE_POLICY + "; Available abstractPolicies: [" + VALID_SIGNATURE_POLICY_3 + ", " + VALID_SIGNATURE_POLICY_4 + "]"));
    }

    /**
     * TestCaseID: Soap-DdocValidationRequest-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Mismatch in documentType and actual document (ddoc and xroad)
     *
     * Expected Result: Error is returned
     *
     * File: xroad-attachment.asice
     */
    @Test
    public void soapDdocValidationRequestNotMatchingDocumentTypeAndActualFileXroad() {
        setTestFilesDirectory("xroad/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("xroad-attachment.asice"));
        post(validationRequestForDocumentExtended(encodedString, "xroad-attachment.ddoc", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }

    /**
     * TestCaseID: Soap-PdfValidationRequest-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Input random base64 string as document with pdf document type
     *
     * Expected Result: Error is returned stating problem in document
     *
     * File: not relevant
     */
    @Test
    public void validationRequestRandomInputAsPdfDocument() {
        String encodedString = "ZCxTgQxDET7/lNizNZ4hrB1Ug8I0kKpVDkHEgWqNjcKFMD89LsIpdCkpUEsFBgAAAAAFAAUAPgIAAEM3AAAAAA==";
        post(validationRequestForDocumentExtended(encodedString, "Valid_IDCard_MobID_signatures.pdf", null, VALID_SIGNATURE_POLICY_3))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is(DOCUMENT_MALFORMED));
    }

    /**
     * TestCaseID: Soap-PdfValidationRequest-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: PDF file, not existing value in signaturePolicy
     *
     * Expected Result: Error is returned
     *
     * File: PdfValidSingleSignature.pdf
     */
    @Test
    public void soapPdfValidationRequestWrongSignaturePolicy() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("PdfValidSingleSignature.pdf"));
        post(validationRequestForDocumentExtended(encodedString, "PdfValidSingleSignature.pdf", null, INVALID_SIGNATURE_POLICY))
                .then()
                .statusCode(200)
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultcode", Matchers.is(CLIENT_FAULT))
                .body(SOAP_ERROR_RESPONSE_PREFIX + ".faultstring", Matchers.is("Invalid signature policy: " + INVALID_SIGNATURE_POLICY + "; Available abstractPolicies: [" + VALID_SIGNATURE_POLICY_3 + ", " + VALID_SIGNATURE_POLICY_4 + "]"));
    }

    /**
     * TestCaseID: Soap-ValidationRequest-PDF-ReportType-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Simple report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File:PdfValidSingleSignature.pdf
     */
    @Test
    public void soapPDFValidationRequestSimpleReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("PdfValidSingleSignature.pdf", REPORT_TYPE_SIMPLE))
                .then()
                .rootPath(SOAP_VALIDATION_CONCLUSION_PREFIX)
                .body("ValidSignaturesCount", Matchers.is("1"));
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-PDF-ReportType-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Detailed report is requested
     *
     * Expected Result: Detailed report is returned
     *
     * File:PdfValidSingleSignature.pdf
     */
    @Test
    public void soapPDFValidationRequestDetailedReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("PdfValidSingleSignature.pdf", REPORT_TYPE_DETAILED))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidSignaturesCount", is("1"))
                .body(SOAP_DETAILED_DATA_PREFIX + ".Signature.ValidationProcessBasicSignature.Conclusion.Indication", is(INDETERMINATE));

        isDetailedReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-PDF-ReportType-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Diagnostic report is requested
     *
     * Expected Result: Diagnostic report is returned
     *
     * File:PdfValidSingleSignature.pdf
     */
    @Test
    public void soapPDFValidationRequestDiagnosticReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("PdfValidSingleSignature.pdf", REPORT_TYPE_DIAGNOSTIC))
                .then()
                .body(SOAP_VALIDATION_CONCLUSION_PREFIX + ".ValidSignaturesCount", is("1"))
                .body(SOAP_DIAGNOSTIC_DATA_PREFIX + ".DocumentName", is("PdfValidSingleSignature.pdf"));
        isDiagnosticReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-BDOC-ReportType-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Simple report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: testECCDemo.bdoc
     */
    @Test
    public void soapBDOCValidationRequestSimpleReportType() {
        setTestFilesDirectory("bdoc/test/timemark/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("testECCDemo.bdoc", REPORT_TYPE_SIMPLE))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-BDOC-ReportType-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Detailed report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: testECCDemo.bdoc
     */
    @Test
    public void soapBDOCValidationRequestDetailedReportType() {
        setTestFilesDirectory("bdoc/test/timemark/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("testECCDemo.bdoc", REPORT_TYPE_DETAILED))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-BDOC-ReportType-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Diagnostic report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: testECCDemo.bdoc
     */
    @Test
    public void soapBDOCValidationRequestDiagnosticReportType() {
        setTestFilesDirectory("bdoc/test/timemark/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("testECCDemo.bdoc", REPORT_TYPE_DIAGNOSTIC))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-DDOC-ReportType-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Simple report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: igasugust1.3.ddoc
     */
    @Test
    public void soapDDOCValidationRequestSimpleReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("igasugust1.3.ddoc", REPORT_TYPE_SIMPLE))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-DDOC-ReportType-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Detailed report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: igasugust1.3.ddoc
     */
    @Test
    public void soapDDOCValidationRequestDetailedReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("igasugust1.3.ddoc", REPORT_TYPE_DETAILED))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-DDOC-ReportType-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Diagnostic report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: igasugust1.3.ddoc
     */
    @Test
    public void soapDDOCValidationRequestDiagnosticReportType() {
        ValidatableResponse response = post(validationRequestForDocumentReportType("igasugust1.3.ddoc", REPORT_TYPE_DIAGNOSTIC))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-ASICE-ReportType-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Simple report is requested
     *
     * Expected Result: Simple report is returned
     *
     * File: Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice
     */
    @Test
    public void soapAsicEValidationRequestSimpleReportType() {
        setTestFilesDirectory("bdoc/test/timestamp/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice", REPORT_TYPE_SIMPLE))
                .then();
        isSimpleReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-ASICE-ReportType-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Detailed report is requested
     *
     * Expected Result: Detailed report is returned
     *
     * File: Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice
     */
    @Test
    public void soapAsicEValidationRequestDetailedReportType() {
        setTestFilesDirectory("bdoc/test/timestamp/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice", REPORT_TYPE_DETAILED))
                .then();
        isDetailedReport(response);
    }

    /**
     * TestCaseID: Soap-ValidationRequest-ASICE-ReportType-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Diagnostic report is requested
     *
     * Expected Result: Diagnostic report is returned
     *
     * File: Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice
     */
    @Test
    public void soapAsicEValidationRequestDiagnosticReportType() {
        setTestFilesDirectory("bdoc/test/timestamp/");
        ValidatableResponse response = post(validationRequestForDocumentReportType("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice", REPORT_TYPE_DIAGNOSTIC))
                .then();
        isDiagnosticReport(response);
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
}
