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

import ee.openeid.siva.common.Constants
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.Tag

@Ignore("SIVA-469")
// Requires new test files and a special mechanism to retrieve them.
@Tag("ManualTest")
// Uses private files and different SiVa settings.
class EuPlugValidationPassSpec extends GenericSpecification {

    @Description("Validation of Lithuania adoc-v2.0 signature")
    def "lithuaniaAsiceAdoc20ValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-LT_MIT-1.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation multiple of Lithuania adoc-v2.0 signatures")
    def "lithuaniaAsiceAdoc20TwoValidSignatures"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-LT_MIT-2.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[1].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[1].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[1].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(2))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(2))
    }

    @Description("Validation of Lithuania adoc-v2.0 signature with warning")
    def "lithuaniaAsiceAdoc20ValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-LT_MIT-5.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Latvian edoc-v2.0 signature")
    def "latviaAsiceEdoc20ValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-LV_EUSO-1.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    //TODO: this file is actually identical to the Signature-A-LV_EUSO-1.asice
    @Description("")
    def "A_LV_EUSO_2Valid"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-LV_EUSO-2.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QES"))
    }

    @Description("Validation of Polish Asic-s with CAdES signature")
    def "polandAsicsCadesValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-PL_KIR-1.asics"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QES"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The certificate is not for eSig at signing time!"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Polish Asic-s with XAdES signature")
    def "polandAsicsXadesValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-PL_KIR-2.asics"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QES"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The certificate is not for eSig at signing time!"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }
    //The file is not valid, revocation outside of 24h timeframe
    @Description("Validation of Slovakia Asic-e with XAdES signature")
    def "slovakiaAsiceXadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-A-SK_DIT-3.asice"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-05-02T09:16:58Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-05-02T09:35:58Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("")
    def "austrianCadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-AT_SIT-1.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-03-31T14:41:57Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of German CAdES signature")
    def "germanyCadesValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-DE_SCI-1.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-03-31T14:41:57Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("")
    def "spainCadesBValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-ES_MIN-1.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B"))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-11T07:30:26Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("")
    def "spainCadesTValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-ES_MIN-2.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-11T07:30:27Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-11T07:30:29Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Italian Cades signatures")
    def "italyCadesTwoValidSignatures"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-IT_BIT-5.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-22T14:07:35Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is(""))
                .body("validationReport.validationConclusion.signatures[1].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[1].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[1].signatureLevel", Matchers.is("NA"))
                .body("validationReport.validationConclusion.signatures[1].claimedSigningTime", Matchers.is("2016-04-22T14:08:35Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(2))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(2))
    }

    @Description("Validation of Poland CAdES B signature")
    def "polandCadesValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-PL_ADS-4.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The signature/seal is not created by a QSCD!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T12:09:38Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is(""))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Poland CAdES T signature")
    def "polandCadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-C-PL_ADS-7.p7m"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("CAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T08:41:09Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-08T08:41:19Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Belgium PAdES B signature")
    def "belgiumPadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-BE_CONN-1.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The signature/seal is not created by a QSCD!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-14T13:28:54Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Belgian PAdES LTA signature")
    def "belgiumPadesValidSignatureWithWarnings"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-BE_CONN-7.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES_BASELINE-LTA")) //No acceptable revocation data
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The signature/seal is not created by a QSCD!"))
                .body("validationReport.validationConclusion.signatures[0].warnings[1].content", Matchers.is("The trust service of the timestamp has not expected type identifier!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-14T14:03:00Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-14T14:03:24Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of German PAdES signature")
    def "germanyPadesValidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-DE_SCI-2.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].errors[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-03-31T14:49:57Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Italian PAdES signature")
    def "italyPadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-IT_MID-1.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-05T08:25:27Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Lithuanian PAdES signature")
    def "lithuaniaPadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-LT_MIT-1.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T10:16:06Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-08T10:16:20Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Lithuanian PAdES signature 2")
    def "lithuaniaPadesValidSignature2"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-LT_MIT-2.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("PAdES-BASELINE-T")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T10:14:19Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-08T10:14:45Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("Validation of Latvian PAdES signature")
    def "latviaPadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-LV_EUSO-1.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-11T13:33:37Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-11T13:33:49Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    //TODO: this file is identical to Signature-P-LV_EUSO-1.pdf
    @Description("")
    def "P_LV_EUSO_2Valid"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-LV_EUSO-2.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].warnings", Matchers.hasSize(0))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-11T13:33:37Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-11T13:33:49Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings[0].content", Matchers.is(Constants.TEST_ENV_VALIDATION_WARNING))
    }

    //The file should not be valid
    @Description("Validation of Polish PAdES signature")
    def "polandPadesValidSignatureWithWarnings"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-PL_ADS-6.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].errors[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T12:56:31Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-08T12:56:42Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))

    }

    // This file should not be valid
    @Description("Validation of Polish PAdES QES signature")
    def "polandPadesValidQesSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-P-PL_ADS-8.pdf"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("validationReport.validationConclusion.signatures[0].Errors[0].content", Matchers.is("The 'issuer-serial' attribute is absent or does not match!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-08T08:47:28Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is("2016-04-08T08:47:38Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("")
    def "X_AT_SIT_1Valid"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-X-AT_SIT-1.xml"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("NA"))
    }

    @Description("")
    def "X_AT_SIT_21Valid"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-X-AT_SIT-21.xml"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("NA"))
    }

    @Description("Validation of Belgian XAdES signature")
    def "belgiumXadesValidSignature"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-X-BE_CONN-1.xml"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The signature/seal is not created by a QSCD!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-18T11:02:37Z"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    @Description("")
    def "X_BE_CONN_21Valid"() {
        expect:
        SivaRequests.validate(validationRequestForEu("Signature-X-BE_CONN-21.xml"))
                .then()
                .body("validationReport.validationConclusion.signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationReport.validationConclusion.signatures[0].signatureFormat", Matchers.is("XAdES-BASELINE-B")) //Minimal LT required
                .body("validationReport.validationConclusion.signatures[0].signatureLevel", Matchers.is("ADESIG_QC"))
                .body("validationReport.validationConclusion.signatures[0].warnings[0].content", Matchers.is("The signature/seal is not created by a QSCD!"))
                .body("validationReport.validationConclusion.signatures[0].claimedSigningTime", Matchers.is("2016-04-18T11:03:29Z"))
                .body("validationReport.validationConclusion.signatures[0].info.bestSignatureTime", Matchers.is(""))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(1))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(1))
    }

    private static Map validationRequestForEu(String file) {
        // TODO: Since these test files are not public the retrieval mechanism needs to be changed.
        return RequestData.validationRequest(file, SignaturePolicy.POLICY_3.name)
    }
}
