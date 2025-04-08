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
import ee.openeid.siva.test.model.DssMessage
import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.SUB_INDICATION_SIG_CRYPTO_FAILURE
import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

class AsicsValidationFailSpec extends GenericSpecification {

    @Description("TST signature not intact")
    def "Given ASiC-S with timestamp with modified signature, then validation should fail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsTSTsignatureModified.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("AsicsTSTsignatureModified.asics"))
                .body("timeStampTokens[0].indication", equalTo(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[0].subIndication", equalTo(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("timeStampTokens[0].error.findAll{it.content}.content", containsInAnyOrder(
                        DssMessage.BBB_CV_ISI_ANS.message,
                        DssMessage.ASCCM_EAA_ANS.getMessage("?", "time-stamp signature")))
    }

    @Description("TST has been corrupted")
    def "Given ASiC-S with broken TST, then validation should fail"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("AsicsTSTsignatureBroken.asics"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Data file changed")
    def "Given ASiC-S with altered datafile, then validation should fail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsWithAlteredDatafile.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("AsicsWithAlteredDatafile.asics"))
                .body("timeStampTokens[0].indication", equalTo(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[0].error[0].content", is(DssMessage.BBB_CV_TSP_IRDOI_ANS.message))
    }

    @Description("Document does not meet the requirements")
    def "Asics with #description should fail"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest(filename))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_DOES_NOT_MEET_THE_REQUIREMENTS)

        where:
        filename                              | description
        "TwoDataFilesAsics.asics"             | "more than one data file"
        "DataFileMissingAsics.asics"          | "no data file"
        "FoldersInAsics.asics"                | "additional folders"
        "MetaInfNotInRoot.asics"              | "META-INF folder not in root"
        "signatureMixedWithTST.asics"         | "signatures.xml files in addition to TST"
        "p7sMixedWithTST.asics"               | "signature.p7s files in addition to TST"
        "evidencerecordXmlMixedWithTST.asics" | "evidence record xml files in addition to TST"
        "evidencerecordErsMixedWithTST.asics" | "evidence record ers files in addition to TST"
        // TODO: SIVA-840 / DSS-3589 (might require separate test, TBD by DSS-3589)
//        "TimestampNameWithPrefix.asics"       | "timestamp name containing prefix"
//        "TimestampNameWithSuffix.asics"       | "timestamp name containing suffix"
    }
}
