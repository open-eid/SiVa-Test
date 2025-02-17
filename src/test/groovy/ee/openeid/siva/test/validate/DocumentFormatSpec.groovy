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

package ee.openeid.siva.test.validate

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class DocumentFormatSpec extends GenericSpecification {

    @Description("Validation of pdf document acceptance")
    def "PAdESDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-lt-sha256-sign.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Validation of bdoc document acceptance")
    def "BdocDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Valid_IDCard_MobID_signatures.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", hasSize(1))
                .body("signatures[0].warnings[0].content", is("Data file 'Proov (2).txt' is empty"))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    @Description("Validation of asice document acceptance")
    def "asiceDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("bdoc21-TS.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of asics document acceptance")
    def "asicsDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Ignore
    //TODO: Test file needed
    @Description("Validation of cades acceptance")
    def "cadesDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(""))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.CAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }
}
