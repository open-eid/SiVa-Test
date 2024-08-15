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

package ee.openeid.siva.test

import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.hamcrest.Matchers

import static ee.openeid.siva.integrationtest.TestData.VALIDATION_CONCLUSION_PREFIX

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class PdfValidationPassSpec extends GenericSpecification {

    @Description("The PDF-file has been signed with certificate that is expired after signing (PAdES Baseline LT)")
    def "validSignaturesRemainValidAfterSigningCertificateExpires"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa1024-not-expired.pdf", SignaturePolicy.POLICY_3.name, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("Veiko Sinivee"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))

    }

    @Description("The PDF-file has been signed with certificate that will expire in 7 days after signing (PAdES Baseline LT)")
    def "certificateExpired7DaysAfterDocumentSigningShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2048-7d.pdf", SignaturePolicy.POLICY_3.name, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))

    }

    @Description("Pdf with single valid signature")
    def "validSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PdfValidSingleSignature.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.notNullValue())
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("The PDF-file has OCSP more than 15 minutes after TS but earlier than 24h")
    def "ocsp15MinutesAfterTsShouldPassWithWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-ocsp-15min1s.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", Matchers.is("The revocation information is not considered as 'fresh'."))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.notNullValue())
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    //TODO SIVA-349 needs investigation why the signature is determined as PAdES_BASELINE_LTA not as PAdES_BASELINE_LT
    @Description("The CRL nextUpdate time is after timestamp time")
    @Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
    def "crlTakenDaysAfterTsShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-lt-CRL-taken-days-later.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.emptyOrNullString())
        //.body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.notNullValue())
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }
}
