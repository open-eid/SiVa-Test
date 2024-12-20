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

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class PdfSignatureCryptographicAlgorithmSpec extends GenericSpecification {

    @Description("SHA512 algorithms (PAdES Baseline LT)")
    def "documentSignedWithSha512CertificateShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha512.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("SHA1 algorithms (PAdES Baseline LT)")
    def "documentSignedWithSha1CertificateShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha1.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

    }

    @Description("ECDSA224 algorithms (PAdES Baseline LT)")
    def "documentSignedWithSha256Ec224AlgoShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-ec224.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_QESIG))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItem("The algorithm ECDSA with key size 224 is too small for signature creation!"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("ECDSA256 algorithms (PAdES Baseline LT)")
    def "documentSignedWithSha256Ec256AlgoShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-ec256.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("RSA1024 algorithms (PAdES Baseline LT)")
    def "documentSignedWithSha256Rsa1024AlgoShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa1024.pdf", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("RSA1023 algorithms (PAdES Baseline LT)")
    def "documentSignedWithRsa1023AlgoShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa1023.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("CRYPTO_CONSTRAINTS_FAILURE_NO_POE"))
                .body("signatures[0].errors.content", hasItem("The past signature validation is not conclusive!"))
    }

    @Description("RSA2047 algorithms (PAdES Baseline LT)")
    def "documentSignedWithRsa2047AlgoShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2047.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

    }

    @Description("RSA2048 algorithms (PAdES Baseline LT)")
    def "documentSignedWithRsa2048AlgoShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PdfValidSingleSignature.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }
}
