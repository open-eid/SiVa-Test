package ee.openeid.siva.test.validate.asice

import ee.openeid.siva.test.DateTimeMatcher
import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description

import java.time.ZoneId
import java.time.ZonedDateTime

import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.*

class AsiceValidityConfirmationRequestSpec extends GenericSpecification {


    @Description("Requesting OCSP during validation is permitted for all countries but EE.")
    def "Given ASiC-E with EE XAdES_BASELINE_T signature, then no OCSP taken and validation fails"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_T.sce"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(TestData.SUB_INDICATION_CERTIFICATE_CHAIN_GENERAL_FAILURE))
                .body("signatures[0].errors.size()", is(2))
                .body("signatures[0].errors.content",
                        hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_NOT_FOUND))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].warnings.content",
                        hasItem("The signature/seal is an INDETERMINATE AdES digital signature!"))
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
    }

    @Description("Requesting OCSP during validation is permitted for all countries but EE.")
    def "Given ASiC-E with non-EE XAdES_BASELINE_T signature, then OCSP is taken and validation passes"() {
        given:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT"))

        expect:
        SivaRequests.validate(RequestData.validationRequest("lv_test_signature_new_card-T.asice"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].warnings.content", hasItems(TestData.REVOCATION_NOT_FRESH))
                .body("signatures[0].info.ocspResponseCreationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))

    }

    @Description("Requesting OCSP during validation is permitted for all countries but EE.")
    def "Given ASiC-E with expired non-EE XAdES_BASELINE_T signature, then OCSP is taken but validation fails"() {
        given:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT"))

        expect:
        SivaRequests.validate(RequestData.validationRequest("lv_test_signature_rsa-T.asice"))
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
}
