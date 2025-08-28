package ee.openeid.siva.test.validate.commonChecks


import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*

import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.hasItem

@Epic("Common policy checks")
@Feature("TS and OCSP time difference check")
@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class TsOcspTimeCheckSpec extends GenericSpecification {

    @Issue("SIVA-907")
    @Issue("SIVA-906")
    @Story("TS and OCSP time difference greater than 15m produces warning")
    def "OCSP freshness warning present if: #containerType and OCSP #ocspTaken"() {
        given: "Compose requestBody for DD4J or DSS validation"
        Map requestBody
        switch (containerType) {
            case "BDOC" -> requestBody = RequestData.validationRequestForDD4J(fileName)
            default -> requestBody = RequestData.validationRequest(fileName)
        }

        expect: "Validation report has dedicated warning"
        SivaRequests.validate(requestBody)
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.indication", hasItem(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", hasItem(TestData.REVOCATION_NOT_FRESH))

        where:
        ocspTaken        | containerType | fileName
        "15m6s after TS" | "ASiC-E"      | "EE_LT_sig_OCSP_15m6s_after_TS.asice"
        "26h after TS"   | "ASiC-E"      | "EE_SER-AEX-B-LT-V-20.asice"

//        "15m6s after TS" | "BDOC"        | "EE_LT_sig_OCSP_15m6s_after_TS.asice"
//        "26h after TS"   | "BDOC"        | "EE_SER-AEX-B-LT-V-20.asice"

        "15m1s after TS" | "PDF"         | "hellopades-lt-sha256-ocsp-15min1s.pdf"
        "28h after TS"   | "PDF"         | "hellopades-lt-sha256-ocsp-28h.pdf"
    }

    @Story("TS and OCSP time difference greater than 15m produces warning")
    def "OCSP freshness warning present if new OCSP is obtained for T-level signature more than 15m after TS"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("lv_test_signature_new_card-T.asice"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.indication", hasItem(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", hasItem(TestData.REVOCATION_NOT_FRESH))
    }

    @Story("Fresh OCSP response doesn´t produce warning")
    def "Signature with fresh OCSP (<15m after TS) should not trigger revocation freshness warning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_LT_sig_OCSP_8m_after_TS.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.indication", hasItem(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
    }

}
