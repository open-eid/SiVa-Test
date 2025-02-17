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

package ee.openeid.siva.test.validate.asice

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class DocumentValidationSpec extends GenericSpecification {

    @Description("Bdoc with two signatures and one unsigned document.")
    def "bdocWithOneUnsignedDocumentShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3f_2s_1f_unsigned.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("HASH_FAILURE"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Container contains a file named <document_3.xml> which is not found in the signature file"))
                .body("signatures[0].warnings.content", hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].subIndication", is("HASH_FAILURE"))
                .body("signatures[1].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Container contains a file named <document_3.xml> which is not found in the signature file"))
                .body("signatures[1].warnings.content", hasItems("The signature/seal is not a valid AdES digital signature!"))
    }

    @Description("Bdoc with two signatures and one document signed by only one signature.")
    def "bdocWithDocumentWithOneSignatureShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3f_2s_1partly_signed.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("FORMAT_FAILURE"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].warnings.content", hasItems("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
    }

    @Description("Bdoc with two signatures and two documents signed by only one signature.")
    def "bdocWithNonOverlapingSignaturesShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3f_2s_2partly_signed.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("FORMAT_FAILURE"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].warnings.content", hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[1].warnings.content", hasItem("The signature/seal is not a valid AdES digital signature!"))

    }

    @Description("Bdoc with two signatures, one unsigned and two partly signed documents.")
    def "bdocWithNonOverlapingSignaturesAndOneUnsignedDocumentShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("4f_2s_all_combinations.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("FORMAT_FAILURE"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <unsigned.txt> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <document_3.xml> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <document_2.docx> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <unsigned.txt> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Container contains a file named <document_2.docx> which is not found in the signature file"))
                .body("signatures[0].errors.content", hasItems("Container contains a file named <unsigned.txt> which is not found in the signature file"))
                .body("signatures[0].warnings.content", hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].subIndication", is("FORMAT_FAILURE"))
    }

    //TODO Should be re-evaluated when https://github.com/open-eid/SiVa/issues/18 is fixed
    @Description("Bdoc with three unsigned documents.")
    def "bdocWithThreeUnsignedDocumentShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("6f_2s_3unsigned.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned.txt> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned2.txt> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned3.txt> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned.txt> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned2.txt> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Manifest file has an entry for file <unsigned3.txt> with mimetype <application/octet-stream> but the signature file for signature S1 does not have an entry for this file"))
                .body("signatures[1].errors.content", hasItems("Container contains a file named <unsigned.txt> which is not found in the signature file"))
                .body("signatures[1].errors.content", hasItems("Container contains a file named <unsigned2.txt> which is not found in the signature file"))
                .body("signatures[1].errors.content", hasItems("Container contains a file named <unsigned3.txt> which is not found in the signature file"))
    }

    @Description("Bdoc with deleted document, named in manifest.")
    def "bdocWithDeletedDocumentNamedInManifestShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2f_2signed_1f_deleted.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_FOUND))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Bdoc with deleted document, also removed from manifest.")
    def "bdocWithRemovedDocumentDeletedFromManifestShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2f_2signed_1f_totally_removed.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].errors.content", hasItems("The signature file for signature S0 has an entry for file <Test document.pdf> with mimetype <application/octet-stream> but the manifest file does not have an entry for this file"))

    }

    // TODO Should be re-evaluated when https://github.com/open-eid/SiVa/issues/18 is fixed
    @Description("Bdoc with one unsigned document, named in manifest.")
    def "bdocWithOneUnsignedDocumentNamedInManifestShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3f_2signed_1unsigned_all_in_manifest.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <Test_1703.pdf> with mimetype <application/octet-stream> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors.content", hasItems("Container contains a file named <Test_1703.pdf> which is not found in the signature file"))
    }

    // TODO  Should be re-evaluated when https://github.com/open-eid/SiVa/issues/18 is fixed
    @Description("Bdoc with one unsigned document, NOT named in manifest.")
    def "bdocWithOneUnsignedDocumentNotNamedInManifestShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3f_2signed_1unsigned_2in_manifest.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItems("Container contains a file named <Test_1703.pdf> which is not found in the signature file"))
    }

    @Description("Bdoc with signed documents.")
    def "bdocWithAllSignedDocumentsShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2f_all_signed.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))

    }
}
