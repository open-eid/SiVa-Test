/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
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
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy")
class SignaturePolicySpec extends GenericSpecification {

    @Ignore
    //TODO: New test file is needed
    @Description("The PDF-file is Ades level")
    def "pdfDocumentAdesNonSscdCompliantShouldFailWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("soft-cert-signature.pdf", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.NA))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", containsString("Signature/seal level do not meet the minimal level required by applied policy"))
                .body("signatures[0].warnings[0].content", is("The trusted certificate doesn't match the trust service"))
                .body("signatures[0].warnings[1].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[2].content", is("The certificate is not for eSig at issuance time!"))
                .body("signatures[0].warnings[3].content", is("The private key is not on a QSCD at issuance time!"))
                .body("signatures[0].warnings[4].content", is("The certificate is not qualified at (best) signing time!"))
                .body("signatures[0].warnings[5].content", is("The certificate is not for eSig at (best) signing time!"))
                .body("signatures[0].warnings[6].content", is("The private key is not on a QSCD at (best) signing time!"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The bdoc is Ades level")
    def "bdocDocumentAdesNonSscdCompliantShouldFailWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", is("Signature/seal level do not meet the minimal level required by applied policy"))
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The private key is not on a QSCD at issuance time!"))
                .body("signatures[0].warnings[2].content", is("The certificate is not qualified at (best) signing time!"))
                .body("signatures[0].warnings[3].content", is("The private key is not on a QSCD at (best) signing time!"))
                .body("signatures[0].warnings", hasSize(4))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The bdoc is Ades signature")
    def "bdocDocumentAdesSigShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The asice is Ades signature")
    def "asiceDocumentAdesSigShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The bdoc is Ades seal")
    def "bdocDocumentAdesSealShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The asice is ades seal")
    def "asiceDocumentAdesSealShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level signature, but do not have SSCD/QSCD compliance")
    def "asiceDocumentAdesQcSigCompliantShouldPassWithWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("testAdesQC.asice", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", hasItem("The signature is not in the Qualified Electronic Signature level"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level signature, but do not have SSCD/QSCD compliance")
    def "bdocDocumentAdesQcSigCompliantShouldPassWithWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("testAdesQC.asice", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level seal, but do not have SSCD/QSCD compliance")
    def "asiceDocumentAdesQCCompliantSealShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_not_qscd_TS.asice", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level seal, but do not have SSCD/QSCD compliance")
    def "bdocDocumentAdesQCCompliantSealShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_not_qscd_TM.bdoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: file needed
    @Description("The certificate is QC level, but do not have SSCD/QSCD compliance and type identifier")
    def "asiceDocumentAdesQCCompliantNoTypeShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is("ADES_QC"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The signature/seal is not created by a QSCD!"))
                .body("signatures[0].warnings[1].content", is("The certificate is not for eSig at signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: file needed
    @Description("The certificate is QC level, but do not have SSCD/QSCD compliance and type identifier")
    def "bdocDocumentAdesQCCompliantNoTypeShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is("ADES_QC"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The signature/seal is not created by a QSCD!"))
                .body("signatures[0].warnings[1].content", is("The certificate is not for eSig at signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level signature")
    def "bdocDocumentQesigShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_TM_OCSP2011.bdoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level signature")
    def "asiceDocumentQesigShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LT.sce", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level seal")
    def "bdocDocumentQesealShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_qscd_TM.bdoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESEAL))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The asice is QES level seal")
    def "asiceDocumentQesealShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_qscd_TS.asice", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESEAL))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level")
    def "bdocDocumentQesNoTypeShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The asice is QES level")
    def "asiceDocumentQesNoTypeShouldPassWithStrictPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-28.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore("SIVA-662")
    // TODO: Test to be completed. Missing test file.
    // Due to missing test file a workaround for manual testing is to use a substitute hashcode test
    // Signature-Level-Re-Evaluation from HashcodeValidationRequestIT.java.
    @Description("Signature level re-evaluation")
    def "signatureLevelReEvaluation"() {
    }

    @Ignore
    //TODO: New testfile is needed
    @Description("The PDF-file is Ades level")
    def "pdfDocumentAdesNonSscdCompliantShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("soft-cert-signature.pdf", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.NA))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The trusted certificate doesn't match the trust service"))
                .body("signatures[0].warnings[1].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[2].content", is("The certificate is not for eSig at issuance time!"))
                .body("signatures[0].warnings[3].content", is("The private key is not on a QSCD at issuance time!"))
                .body("signatures[0].warnings[4].content", is("The certificate is not qualified at (best) signing time!"))
                .body("signatures[0].warnings[5].content", is("The certificate is not for eSig at (best) signing time!"))
                .body("signatures[0].warnings[6].content", is("The private key is not on a QSCD at (best) signing time!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: New testfile is needed
    @Description("The bdoc is Ades level")
    def "bdocDocumentAdesNonSscdCompliantShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("allkiri_ades.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The private key is not on a QSCD at issuance time!"))
                .body("signatures[0].warnings[2].content", is("The certificate is not qualified at (best) signing time!"))
                .body("signatures[0].warnings[3].content", is("The private key is not on a QSCD at (best) signing time!"))
                .body("signatures[0].warnings", hasSize(4))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The bdoc is ADES level signature")
    def "bdocDocumentAdesSigShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The asice is Ades level signature")
    def "asiceDocumentAdesSigShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The bdoc is Ades seal")
    def "bdocDocumentAdesSealShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: test file needed
    @Description("The asice is Ades level seal")
    def "asiceDocumentAdesSealShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The certificate is not qualified at issuance time!"))
                .body("signatures[0].warnings[1].content", is("The signature/seal is not created by a QSCD!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level signature, but do not have SSCD/QSCD compliance")
    def "asiceDocumentAdesQcSicShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("testAdesQC.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level signature, but do not have SSCD/QSCD compliance")
    def "bdocDocumentAdesQcSigShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("testAdesQC.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESIG_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level seal, but do not have SSCD/QSCD compliance")
    def "asiceDocumentAdesQcCompliantSealShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_not_qscd_TS.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The certificate is QC level seal, but do not have SSCD/QSCD compliance")
    def "bdocDocumentAdesQCCompliantSealShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_not_qscd_TM.bdoc", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.ADESEAL_QC))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: file needed
    @Description("The certificate is QC level, but do not have SSCD/QSCD compliance and type identifier")
    def "asiceDocumentAdesQCCompliantNoTypeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is("ADES_QC"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The signature/seal is not created by a QSCD!"))
                .body("signatures[0].warnings[1].content", is("The certificate is not for eSig at signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: file needed
    @Description("The certificate is QC level, but do not have SSCD/QSCD compliance and type identifier")
    def "bdocDocumentAdesQCCompliantNoTypeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is("ADES_QC"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings[0].content", is("The signature/seal is not created by a QSCD!"))
                .body("signatures[0].warnings[1].content", is("The certificate is not for eSig at signing time!"))
                .body("signatures[0].warnings", hasSize(2))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level signature")
    def "bdocDocumentQesigShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_TM_OCSP2011.bdoc", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level signature")
    def "asiceDocumentQesigShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LT.sce", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level seal")
    def "bdocDocumentQesealShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_qscd_TM.bdoc", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESEAL))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The asice is QES level seal")
    def "asiceDocumentQesealShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4828_tempel_qscd_TS.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESEAL))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The bdoc is QES level")
    def "bdocDocumentQesNoTypeShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The asice is QES level")
    def "asiceDocumentQesNoTypeShouldPassWithGivenPolicy"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-28.asice", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_3.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_3.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_3.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore("SIVA-662")
    // TODO: Test to be completed. Missing test file.
    // Due to missing test file a workaround for manual testing is to use a substitute hashcode test
    // Signature-Level-Re-Evaluation-2 from HashcodeValidationRequestIT.java.
    @Description("Signature level not re-evaluated in POLv3")
    def "signatureLevelNoReEvaluation"() {
    }

    @Description("The PDF-file is missing an OCSP or CRL")
    def "pdfDocumentWithoutRevocationInfoShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PadesProfileT.pdf", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_NOT_FOUND))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    //TODO SIVA-349 needs investigation why the signature is determined as PAdES_BASELINE_LTA not as PAdES_BASELINE_LT
    @Description("The PDF-file with included CRL")
    def "pdfDocumentWithCrlAsRevocationInfoShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PadesProfileLtWithCrl.pdf", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", is(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", is(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", is(SignaturePolicy.POLICY_4.url))
        //.body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }
}
