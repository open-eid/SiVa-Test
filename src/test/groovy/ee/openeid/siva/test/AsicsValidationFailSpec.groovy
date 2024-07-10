/*
 * Copyright 2017 - 2024 Riigi Infosüsteemi Amet
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

import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import org.apache.http.HttpStatus
import org.hamcrest.Matchers

import static ee.openeid.siva.integrationtest.TestData.VALIDATION_CONCLUSION_PREFIX

class AsicsValidationFailSpec extends GenericSpecification {

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
    def "moreThanOneDataFileInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("TwoDataFilesAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
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
    def "noDataFileInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("DataFileMissingAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
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
    def "additionalFoldersInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("FoldersInAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
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
    def "metaInfFolderNotInRootAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("MetaInfNotInRoot.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
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
    def "signatureFilesInAddtionToTstAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("signatureMixedWithTST.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
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
    def "modifiedTstShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsTSTsignatureModified.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("validatedDocument.filename", Matchers.is("AsicsTSTsignatureModified.asics"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", Matchers.is("Signature not intact"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"))
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
    def "brokenTstAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("AsicsTSTsignatureBroken.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document malformed or not matching documentType"))
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
    def "dataFileChangedAsicsShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DatafileAlteredButStillValid.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("validatedDocument.filename", Matchers.is("DatafileAlteredButStillValid.asics"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", Matchers.is("Signature not intact"))
                .body("timeStampTokens[0].certificates[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].certificates[0].type", Matchers.is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
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
    def "evidencereecordFilesInAddtionToTstAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("evidencerecordMixedWithTST.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))
    }


    // TODO: test that replaces most tests above
    //  set name and make all readable
    def "Asics with #description should fail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest(filename))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is("Document does not meet the requirements"))

        where:
        filename                           | description
        "TwoDataFilesAsics.asics"          | "more than one data file"
        "DataFileMissingAsics.asics"       | "no data file"
        "FoldersInAsics.asics"             | "additional folders"
        "MetaInfNotInRoot.asics"           | "META-INF folder not in root"
        "signatureMixedWithTST.asics"      | "signature files in addition to TST"
        "evidencerecordMixedWithTST.asics" | "evidence record files in addition to TST"
    }
}
