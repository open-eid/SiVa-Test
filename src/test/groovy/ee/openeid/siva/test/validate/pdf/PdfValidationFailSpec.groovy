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
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class PdfValidationFailSpec extends GenericSpecification {

    @Description("The PDF-file has been signed with expired certificate (PAdES Baseline T)")
    def "signaturesMadeWithExpiredSigningCertificatesAreInvalid"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-rsa1024-sha1-expired.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItem(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].warnings.content[0]", is("The signature/seal is an INDETERMINATE AdES digital signature!"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF-file has been signed with revoked certificate (PAdES Baseline LT)")
    def "documentSignedWithRevokedCertificateShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades_lt_revoked.pdf", SignaturePolicy.POLICY_3, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].signedBy", is("NURM,AARE,38211015222"))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("REVOKED_NO_POE"))
                .body("signatures[0].errors.content", hasItem("The past signature validation is not conclusive!"))
                .body("signatures[0].claimedSigningTime", is("2016-06-29T08:38:31Z"))
                .body("signatures[0].warnings[0].content", is("The signature/seal is an INDETERMINATE AdES digital signature!"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    //TODO SIVA-349 needs investigation why the signature level is determined as INDETERMINATE_ADESIG not as INDETERMINATE_QESIG
    @Description("The PDF-file has been signed with certificate which has no non repudiation key usage attribute (PAdES Baseline LT)")
    def "signingCertificateWithoutNonRepudiationKeyUsageAttributeShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-lt-sha256-auth.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
        //.body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("36706020210"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("CHAIN_CONSTRAINTS_FAILURE"))
                .body("signatures[0].errors.content", contains(
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        NOT_EXPECTED_KEY_USAGE,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: Needs new test file
    @Description("hellopadess been signed with an expired certificate, where signing time is within the original validity period of the certificate, but OCSP confirmation and Time Stamp are current date (PAdES Baseline LT).")
    def "documentSignedWithExpiredRsa2048CertificateShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2048-expired.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("NO_POE"))
                .body("signatures[0].errors.content", hasItem("The past signature validation is not conclusive!"))
                .body("signatures[0].warnings", hasSize(0))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Ignore
    //TODO: Test file needed
    @Description("hellopadess been signed with an expired certificate, where signing time is within the original validity period of the certificate, but OCSP confirmation and Time Stamp are current date (PAdES Baseline LT).")
    def "documentSignedWithExpiredSha256CertificateShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa1024-expired2.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("The PDF-file has OCSP almost 24h before TS")
    @Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
    def "ocspAlmost24hBeforeTsShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2048-ocsp-before-ts.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", is("OCSP response production time is before timestamp time"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }
}
