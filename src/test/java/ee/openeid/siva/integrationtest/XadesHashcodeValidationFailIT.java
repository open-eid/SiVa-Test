/*
 * Copyright 2018 - 2023 Riigi Infosüsteemi Amet
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

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static ee.openeid.siva.integrationtest.TestData.*;

@Tag("IntegrationTest")
public class XadesHashcodeValidationFailIT extends SiVaRestTests {
    private static final String DEFAULT_TEST_FILES_DIRECTORY = "xades/";
    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Fail-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Data file hash algorithm do not match signature hash algorithm
     *
     * Expected Result: Validation fails
     *
     * File: Valid_XAdES_LT_TM.xml
     **/
    @Test
    public void dataFileHashAlgorithmDoesNotMatchWithSignatureDataFileHashAlgorithm() {
        postHashcodeValidation(validationRequestHashcode("Valid_XAdES_LT_TM.xml", null, null, "test.txt", HASH_ALGO_SHA512, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].indication", Matchers.is("INDETERMINATE"))
                .body("signatures[0].subIndication", Matchers.is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", Matchers.hasItem(REFERENCE_DATA_NOT_FOUND))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2019-02-05T13:36:23Z"))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validSignaturesCount", Matchers.is(0));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Fail-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Hashes do not match
     *
     * Expected Result: Validation fails
     *
     * File: Valid_XAdES_LT_TM.xml
     **/
    @Test
    public void dataFileHashDoesNotMatchWithSignatureFile() {
        postHashcodeValidation(validationRequestHashcode("Valid_XAdES_LT_TM.xml", null, null, "test.txt", HASH_ALGO_SHA256, "kl2ZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("HASH_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItem(REFERENCE_DATA_NOT_INTACT))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2019-02-05T13:36:23Z"))
                .body("validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validSignaturesCount", Matchers.is(0));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Fail-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Wrong data file name is used
     *
     * Expected Result: Validation report is returned
     *
     * File: Valid_XAdES_LT_TS.xml
     **/
    @Test
    public void dataFileFilenameDoesNotMatchWithSignatureFile() {
        postHashcodeValidation(validationRequestHashcode("Valid_XAdES_LT_TS.xml", null, null, "wrongDataFileName.jpg", HASH_ALGO_SHA256, "Sj/WcgsM57hpCiR5E8OycJ4jioYwdHzz3s4e5LXditA="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].indication", Matchers.is("INDETERMINATE"))
                .body("signatures[0].subIndication", Matchers.is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", Matchers.hasItem(REFERENCE_DATA_NOT_FOUND))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2019-02-05T13:27:24Z"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validSignaturesCount", Matchers.is(0));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Fail-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Invalid signature in XAdES
     *
     * Expected Result: Validation report is returned
     *
     * File: Valid_XAdES_LT_TM.xml
     **/
    @Test
    public void invalidSignature() {
        postHashcodeValidation(validationRequestHashcode("Invalid_XAdES_LT_TM.xml", null, null, "test.txt", HASH_ALGO_SHA256, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2019-02-05T13:36:23Z"))
                .body("validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validSignaturesCount", Matchers.is(0));
    }

    /**
     * TestCaseID: Xades-Hashcode-Validation-Fail-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Invalid signature in XAdES
     *
     * Expected Result: Error is given
     *
     * File: Valid_XAdES_LT_TM.xml
     **/
    @Test
    public void invalidBase64Signature() {
        postHashcodeValidation(validationRequestHashcode("Invalid_base64_XAdES_LT_TM.xml", null, null, "test.txt", HASH_ALGO_SHA256, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2019-02-05T13:36:23Z"))
                .body("validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validSignaturesCount", Matchers.is(0));
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
}
