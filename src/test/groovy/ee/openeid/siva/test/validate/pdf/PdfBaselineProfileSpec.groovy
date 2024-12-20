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

package ee.openeid.siva.test.validate.pdf

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
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
class PdfBaselineProfileSpec extends GenericSpecification {

    @Description("The PDF has PAdES-B profile signature polv3")
    def "baselineProfileBDocumentShouldFailpolv3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-b-sha256-auth.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[0].signatureLevel", is(SignatureLevel.NOT_ADES))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", contains(
                        SIG_UNEXPECTED_FORMAT,
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        NOT_EXPECTED_KEY_USAGE,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("signatures[0].warnings", hasSize(4))
                .body("signatures[0].certificates.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2011"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-T profile signature polv3")
    def "baselineProfileTDocumentShouldFailpolv3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-t-live-aj.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].warnings", hasSize(1))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("JUHANSON,ALLAN,38608014910"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-LT profile signature polv3")
    def "baselineProfileLTDocumentShouldPasspolv3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-lt-sha256-sign.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.size()", is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-LT profile signature polv4")
    def "baselineProfileLTDocumentShouldPasspolv4"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-lt-sha256-sign.pdf", SignaturePolicy.POLICY_4))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-LTA profile signature polv3")
    def "baselineProfileLTADocumentShouldPasspolv3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LTA))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.size()", is(4))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("JUHANSON,ALLAN,38608014910"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-LTA profile signature polv4")
    def "baselineProfileLTADocumentShouldPasspolv4"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", SignaturePolicy.POLICY_4))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LTA))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.size()", is(4))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("JUHANSON,ALLAN,38608014910"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF has PAdES-LT and B profile signature")
    def "documentWithBaselineProfilesBAndLTSignaturesShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-b.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[1].signatureLevel", is(SignatureLevel.NOT_ADES))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].errors.content", hasItem(CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("signatures[1].warnings.content", hasItem(VALID_VALIDATION_PROCESS_VALUE_35))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))

    }

    @Description("PDF document message digest attribute value does not match calculate value")
    def "documentMessageDigestAttributeValueDoesNotMatchCalculatedValue"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt1-lt2-wrongDigestValue.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[1].signatureLevel", is(SignatureLevel.NOT_ADES_QC))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].subIndication", is("HASH_FAILURE"))
                .body("signatures[1].errors[0].content", is(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }

    @Description("PDF file with a serial signature")
    def "documentSignedWithMultipleSignersSerialSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt1-lt2-Serial.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))
    }
}
