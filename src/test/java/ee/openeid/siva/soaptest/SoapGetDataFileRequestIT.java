/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
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

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;


@Tag("IntegrationTest")
public class SoapGetDataFileRequestIT extends SiVaSoapTests {

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
    }

    private static final String DEFAULT_TEST_FILES_DIRECTORY = "ddoc/get_data_files/";

    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Input empty values
     *
     * Expected Result: Error is returned
     *
     * File: not relevant
     *
     **/
    @Test
    public void soapGetDataFileRequestEmptyInputs() {
        postDataFiles(validationRequestForDocumentDataFilesExtended("", ""))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_NOT_BASE64));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Input empty body
     *
     * Expected Result: Error is returned
     *
     * File: not relevant
     *
     **/
    @Test
    public void soapGetDataFileRequestEmptyBody() {
        String emptyRequestBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        postDataFiles(emptyRequestBody)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_NOT_BASE64));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Element DocumentType is removed from the body
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeRemoved(){
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        String request = validationRequestForDocumentDataFilesExtended(encodedString, "valid_XML1_3.ddoc");
        String invalidRequest = request.replace("<Filename>valid_XML1_3.ddoc</Filename>", "");
        postDataFiles(invalidRequest)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is("Invalid file name. Can only return data files for DDOC type containers."));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Element Document is removed from the body
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentRemoved(){
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        String request = validationRequestForDocumentDataFilesExtended(encodedString, "DDOC");
        String invalidRequest = request.replace("<Document>"+encodedString+"</Document>", "");
        postDataFiles(invalidRequest)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_NOT_BASE64));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Element DocumentType is duplicated in the body with different value
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeDuplicated(){
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        String request = validationRequestForDocumentDataFilesExtended(encodedString, "test_file.DDOC");
        String invalidRequest = request.replace("<Filename>test_file.DDOC</Filename", "<Filename>test.DDOC</Filename><Filename>test.BDOC</Filename>");
        postDataFiles(invalidRequest)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.startsWith("Unmarshalling Error: cvc-complex-type.2.4.d: Invalid content was found starting with element 'Filename'. No child element is expected at this point."));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Additional element Filename is added to  the body
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestMoreKeysThanExpected() {
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        String invalidRequest = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soap=\"http://soap.webapp.siva.openeid.ee/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <soap:GetDocumentDataFiles>\n" +
                "         <soap:DataFilesRequest>\n" +
                "            <Document>" + encodedString + "</Document>\n" +
                "			 <Filename>valid_XML1_3.ddoc</Filename>\n" +
                "            <DocumentType>DDOC</DocumentType>\n" +
                "            </soap:DataFilesRequest>\n" +
                "      </soap:GetDocumentDataFiles>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        postDataFiles(invalidRequest)
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode", Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring", Matchers.startsWith("Unmarshalling Error: cvc-complex-type.2.4.d: Invalid content was found starting with element 'DocumentType'. No child element is expected at this point. "));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-7
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title: Value for element Document was changed
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentValueIsChanged(){
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        String invalidEncodedString = encodedString.replace("PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZ", "AAAAAA");
        postDataFiles(validationRequestForDocumentDataFilesExtended(invalidEncodedString, "test.DDOC"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));

    }

    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-9
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to BDOC when actual is DDOC
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeChangedToBdoc() {
        setTestFilesDirectory("ddoc/test/timemark/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.BDOC"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(INVALID_DATA_FILE_FILENAME));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-10
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to PDF when actual is DDOC
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeChangedToPdf() {
        setTestFilesDirectory("ddoc/test/timemark/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.PDF"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(INVALID_DATA_FILE_FILENAME));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-11
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to XROAD when actual is DDOC
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeChangedToXROAD() {
        setTestFilesDirectory("ddoc/test/timemark/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.XROAD"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(INVALID_DATA_FILE_FILENAME));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-12
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to unsupported format JPG when actual is DDOC
     *
     * Expected Result: Error is returned
     *
     * File: valid_XML1_3.ddoc
     *
     **/
    @Test
    public void soapGetDataFileRequestDocumentTypeChangedToUnsupported() {
        setTestFilesDirectory("ddoc/test/timemark/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("valid_XML1_3.ddoc"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.JPG"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(INVALID_DATA_FILE_FILENAME));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-13
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to DDOC when actual is PDF
     *
     * Expected Result: Error is returned
     *
     * File: PdfValidSingleSignature.pdf
     *
     **/
    @Test
    public void soapGetDataFileRequestNotMatchingDocumentTypeAndActualFilePdf() {
        setTestFilesDirectory("document_format_test_files/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("PdfValidSingleSignature.pdf"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.DDOC"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }
    /**
     *
     * TestCaseID: Soap-Validation-Request-For-Data-Files-14
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#data-files-request-interface
     *
     * Title:  DocumentType was changed to DDOC when actual is BDOC
     *
     * Expected Result: Error is returned
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     *
     **/
    @Test
    public void soapGetDataFileRequestNotMatchingDocumentTypeAndActualFileBdoc() {
        setTestFilesDirectory("document_format_test_files/");
        String encodedString = Base64.encodeBase64String(readFileFromTestResources("Valid_IDCard_MobID_signatures.bdoc"));
        postDataFiles(validationRequestForDocumentDataFilesExtended(encodedString, "test.DDOC"))
                .then()
                .statusCode(HttpStatus.SC_OK)
                .body("Envelope.Body.Fault.faultcode",Matchers.is(CLIENT_FAULT))
                .body("Envelope.Body.Fault.faultstring",Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE));
    }
    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }
}
