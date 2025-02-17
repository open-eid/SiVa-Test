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

package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.startsWith

class AsicsValidationFailSpec extends GenericSpecification {

    @Description("Only one datafile is allowed in ASIC-s")
    def "moreThanOneDataFileInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("TwoDataFilesAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }

    @Description("No data file in ASIC-s")
    def "noDataFileInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("DataFileMissingAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }

    @Description("more folders that META-INF in ASIC-s")
    def "additionalFoldersInAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("FoldersInAsics.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }

    @Description("META-INF folder not in root of container")
    def "metaInfFolderNotInRootAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("MetaInfNotInRoot.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }

    @Description("Not allowed files in META-INF folder")
    def "signatureFilesInAddtionToTstAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("signatureMixedWithTST.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("TST not intact")
    def "modifiedTstShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsTSTsignatureModified.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("AsicsTSTsignatureModified.asics"))
                .body("timeStampTokens[0].indication", is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", is("Signature not intact"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
    }

    @Description("TST has been corrupted")
    def "brokenTstAsicsShouldFail"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("AsicsTSTsignatureBroken.asics"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Data file changed")
    def "dataFileChangedAsicsShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DatafileAlteredButStillValid.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("DatafileAlteredButStillValid.asics"))
                .body("timeStampTokens[0].indication", is("TOTAL-FAILED"))
                .body("timeStampTokens[0].error[0].content", is("Signature not intact"))
                .body("timeStampTokens[0].certificates[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].certificates[0].type", is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
    }

    @Description("Exluding files in META-INF folder together with TST")
    def "evidencereecordFilesInAddtionToTstAsicsShouldFail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("evidencerecordMixedWithTST.asics"))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))
    }


    // TODO: test that replaces most tests above
    //  set name and make all readable
    @Description("")
    def "Asics with #description should fail"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest(filename))
                .then().statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", is("document"))
                .body("requestErrors[0].message", is("Document does not meet the requirements"))

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
