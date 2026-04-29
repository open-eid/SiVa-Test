/*
 * Copyright 2025 - 2026 Riigi Infosüsteemi Amet
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

import ee.openeid.siva.test.*
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response
import spock.lang.Ignore

import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.*

@Epic("Request OCSP during T-level signature validation")
class AdditionalOcspRequestSpec extends GenericSpecification {

    @Story("Requesting OCSP for EE signature is not allowed")
    def "OCSP is not requested for BASELINE_T level EE signature: #signatureType"() {
        when: "validate ASiC-E/PDF with EE signature"
        Response response = SivaRequests.validate(RequestData.validationRequest(filename))

        then: "no new OCSP info is not present"
        response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signatures[0].errors.size()", is(2))
                .body("signatures[0].errors.content",
                        hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_NOT_FOUND))
                .body("signatures[0].warnings.content",
                        hasItem("The signature/seal is an INDETERMINATE AdES digital signature!"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

        where:
        filename                             | signatureType | containerType || signatureFormat
        "TEST_ESTEID2018_ASiC-E_XAdES_T.sce" | "XAdES"       | "ASiC-E"      || SignatureFormat.XAdES_BASELINE_T
        "pades-baseline-t-live-aj.pdf"       | "PAdES"       | "PDF"         || SignatureFormat.PAdES_BASELINE_T
        "TEST_ESTEID2018_ASiC-E_CAdES_T.sce" | "CAdES"       | "ASiC-E"      || SignatureFormat.CAdES_BASELINE_T
    }

    @Story("Requesting OCSP for EE signature is not allowed")
    def "OCSP is not requested for BASELINE_T level EE XAdES signature in BDOC"() {
        when: "validate as BDOC with EE signature"
        Response response = SivaRequests.validate(RequestData.validationRequestForDD4J("TEST_ESTEID2018_ASiC-E_XAdES_T.sce"))

        then: "no new OCSP info is not present"
        response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signatures[0].errors.size()", is(3))
                .body("signatures[0].errors.content",
                        hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_NOT_FOUND))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].warnings.content",
                        hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
    }

    @Story("Requesting OCSP for EE signature is not allowed")
    def "OCSP is not requested for EE signature with #signatureLevel"() {
        when: "validate EE signature"
        Response response = SivaRequests.validate(RequestData.validationRequest(filename))

        then: "no new OCSP info is not present"
        def validationReport = response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
        switch (ocspResponseCreationTime) {
            case "" -> validationReport.body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
            default -> validationReport.body("signatures[0].info.ocspResponseCreationTime", is(ocspResponseCreationTime))
        }

        where:
        signatureLevel | filename                               | ocspResponseCreationTime
        "B-level"      | "TEST_ESTEID2018_ASiC-E_XAdES_B.sce"   | ""
        "LT-level"     | "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"  | "2024-09-13T14:14:36Z"
        "LTA-level"    | "TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce" | "2024-09-13T14:14:47Z"
    }

    @Issue("SIVA-775")
    @Story("Requesting OCSP for non-EE signature is allowed")
    def "OCSP is requested for non-EE signature with #signatureLevel"() {
        given: "record present time to validate OCSP info freshness"
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT")).truncatedTo(ChronoUnit.SECONDS)

        when: "validate non-EE signature"
        Response response = SivaRequests.validate(RequestData.validationRequest(filename))

        then: "fresh OCSP info is present"
        response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].info.ocspResponseCreationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signatures[0].certificates.commonName", hasItem("DEMO LV eID ICA 2021 OCSP"))
                .body("signatures[0].certificates.content", hasItem(startsWith("MIIFEjCCAvqgAwIBAgIQf64G0LIX5sZnYbGDetZCETANBgkqhkiG9w0BAQsFADCBgzELMAkG")))
                .body("signatures[0].certificates.issuer.commonName", hasItem("DEMO LV eID ICA 2021"))
                .body("signatures[0].certificates.issuer.content", hasItem(startsWith("MIIHoDCCBYigAwIBAgIQWenLZXqRSFhgGW2H")))
                .body("signatures[0].certificates.type", hasItem("REVOCATION"))

        where:
        signatureLevel | filename
        "B-level"      | "lv_test_signature_new_card-B.asice"
//        "LT-level"     | "lt_test_signature-LT.asice" //In report ocspResponseCreationTime is populated randomly (new vs existing)
//        "LTA-level"    | "lv_test_signature-LTA.asice" //In report ocspResponseCreationTime is populated randomly (new vs existing)
    }

    // TODO: Needs testfiles for PAdES and CAdES signatures
    @Story("Requestion OCSP for non-EE country signature is allowed")
    def "OCSP is requested for BASELINE_T level non-EE country signature and signature is valid"() {
        given:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT")).truncatedTo(ChronoUnit.SECONDS)

        when: "validate non-ee T-level signature"
        Response response = SivaRequests.validate(RequestData.validationRequest("lv_test_signature_new_card-T.asice"))

        then: "fresh OCSP info is present, signature is valid"
        response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.ocspResponseCreationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signatures[0].certificates.commonName", hasItem("DEMO LV eID ICA 2021 OCSP"))
                .body("signatures[0].certificates.content", hasItem(startsWith("MIIFEjCCAvqgAwIBAgIQf64G0LIX5sZnYbGDetZCETANBgkqhkiG9w0BAQsFADCBgzELMAkG")))
                .body("signatures[0].certificates.issuer.commonName", hasItem("DEMO LV eID ICA 2021"))
                .body("signatures[0].certificates.issuer.content", hasItem(startsWith("MIIHoDCCBYigAwIBAgIQWenLZXqRSFhgGW2H")))
                .body("signatures[0].certificates.type", hasItem("REVOCATION"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Ignore("Needs a new testfile as CA certificate expired 02-03-2026 and no OCSP is taken after that")
    @Description("Requesting OCSP during validation is permitted for all countries but EE.")
    def "Given ASiC-E with expired non-EE XAdES_BASELINE_T signature, then OCSP is taken but validation fails"() {
        given:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT")).truncatedTo(ChronoUnit.SECONDS)

        expect:
        SivaRequests.validate(RequestData.validationRequest("lv_test_signature_rsa-T_CA_expired.asice"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.size()", is(3))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE,
                        TestData.VALID_VALIDATION_PROCESS_ERROR_VALUE_5, TestData.REVOCATION_NOT_CONSISTENT))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].warnings.content", hasItems(TestData.REVOCATION_NOT_FRESH,
                        "The signature/seal is an INDETERMINATE AdES digital signature!"))
                .body("signatures[0].info.ocspResponseCreationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
    }

    @Story("Requestion OCSP for non-EE country signature is allowed")
    def "OCSP is not requested for non-EE level signature when CA is expired"() {
        when: "validate expired non-EE T-level signature"
        Response response = SivaRequests.validate(RequestData.validationRequest("lv_test_signature_rsa-T_CA_expired.asice"))

        then: "no OCSP info present"
        response.then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
    }
}
