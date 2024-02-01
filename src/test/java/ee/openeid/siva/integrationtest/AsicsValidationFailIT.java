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

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static ee.openeid.siva.integrationtest.TestData.VALIDATION_CONCLUSION_PREFIX;

@Tag("IntegrationTest")
public class AsicsValidationFailIT extends SiVaRestTests {

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
    }

    private static final String DEFAULT_TEST_FILES_DIRECTORY = "asics/";

    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }

    /**
     * TestCaseID: Asics-ValidationFail-1
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: Only one datafile is allowed in ASIC-s
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: TwoDataFilesAsics.asics
     */
    @Test
    public void moreThanOneDataFileInAsicsShouldFail() {
        post(validationRequestFor("TwoDataFilesAsics.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-2
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: No data file in ASIC-s
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: DataFileMissingAsics.asics
     */
    @Test
    public void noDataFileInAsicsShouldFail() {
        post(validationRequestFor("DataFileMissingAsics.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-3
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: more folders that META-INF in ASIC-s
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: FoldersInAsics.asics
     */
    @Test
    public void additionalFoldersInAsicsShouldFail() {
        post(validationRequestFor("FoldersInAsics.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-4
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: META-INF folder not in root of container
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: MetaInfNotInRoot.asics
     */
    @Test
    public void metaInfFolderNotInRootAsicsShouldFail() {
        post(validationRequestFor("MetaInfNotInRoot.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-5
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: Not allowed files in META-INF folder
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: signatureMixedWithTST.asics
     */
    @Test
    public void signatureFilesInAddtionToTstAsicsShouldFail() {
        post(validationRequestFor("signatureMixedWithTST.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-6
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: TST not intact
     * <p>
     * Expected Result: The validation should fail
     * <p>

     * File: AsicsTSTsignatureModified.asics
     */
    @Test
    public void modifiedTstShouldFail() {
        post(validationRequestFor("AsicsTSTsignatureModified.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("validatedDocument.filename", Matchers.is("AsicsTSTsignatureModified.asics"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", Matchers.is("Signature not intact"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-7
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: TST has been corrupted
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: AsicsTSTsignatureBroken.asics
     */
    @Test
    public void brokenTstAsicsShouldFail() {
        post(validationRequestFor("AsicsTSTsignatureBroken.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document malformed or not matching documentType"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-8
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: Data file changed
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: DatafileAlteredButStillValid.asics
     */
    @Test
    public void dataFileChangedAsicsShouldFail() {
        post(validationRequestFor("DatafileAlteredButStillValid.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("validatedDocument.filename", Matchers.is("DatafileAlteredButStillValid.asics"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", Matchers.is("Signature not intact"))
                .body("timeStampTokens[0].certificates[0].commonName",  Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].certificates[0].type",  Matchers.is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content",  Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"));
    }

    /**
     * TestCaseID: Asics-ValidationFail-9
     * <p>
     * TestType: Automated
     * <p>
     * Requirement:
     * <p>
     * Title: Exluding files in META-INF folder together with TST
     * <p>
     * Expected Result: The validation should fail
     * <p>
     * File: evidencerecordMixedWithTST.asics
     */
    @Test
    public void evidencereecordFilesInAddtionToTstAsicsShouldFail() {
        post(validationRequestFor("evidencerecordMixedWithTST.asics"))
                .then()
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"));
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }
}
