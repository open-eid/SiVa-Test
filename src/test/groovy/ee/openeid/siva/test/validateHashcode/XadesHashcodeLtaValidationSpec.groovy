/*
 * Copyright 2024 - 2026 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test.validateHashcode

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Epic("Signature validation (hashcode)")
@Feature("XAdES LTA hashcode validation")
@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class XadesHashcodeLtaValidationSpec extends GenericSpecification {

    @Story("Validate LTA hashcode with default settings")
    def "Validate LTA hashcode fails without setting validation level: #description"() {
        when: "request is sent without validation level"
        Response response = SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest(fileName))

        then: "signature validation fails"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(indication))
                .body("validationLevel", is("ARCHIVAL_DATA"))
                .body("signatures[0].errors.content", hasItem(TS_MESSAGE_NOT_INTACT))
                .body("signatures[0].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                                      | fileName                                       || indication
        "TS certificate expired"                         | "TEST_XAdES_LTA.xml"                           || "TOTAL-FAILED"
        "TS/OCSP certificates expired"                   | "TEST_XAdES_LTA-AiaOcsp-Expired-202308.xml"    || "TOTAL-FAILED"
        "all certificates expired"                       | "3_signatures_TM_LT_LTA.xml"                   || "TOTAL-FAILED"
        "signed with expired OCSP"                       | "esteid2018signerAiaOcspExpiredLTA.xml"        || "INDETERMINATE"
        "not trusted ATS"                                | "2xLTA-SK+Entrust.xml"                         || "TOTAL-FAILED"
        "multiple ATS"                                   | "TEST_XAdES_LTA-2xArchivetimestamps.xml"       || "TOTAL-FAILED"
        "Qualified TS + Not-qualified ATS"               | "LTA_QTSA_TSA.xml"                             || "TOTAL-FAILED"
        "Qualified TS + Not-qualified and Qualified ATS" | "LTA_QTSA_TSA_QTSA.xml"                        || "TOTAL-FAILED"
        "Not-qualified TS + Qualified ATS"               | "LTA_TSA_QTSA.xml"                             || "TOTAL-FAILED"
        "TS replaced"                                    | "TEST_XAdES_LTA-Ts-Replaced.xml"               || "TOTAL-FAILED"
        "ATS replaced"                                   | "TEST_XAdES_LTA-Archivetimestamp-Replaced.xml" || "TOTAL-FAILED"
    }

    @Story("Validate LTA hashcode with validation level set")
    def "Validate LTA hashcode fails with ArchivalData validation level: #description"() {
        given: "validation level is set to ArchivalData"
        Map requestBody = RequestData.hashcodeValidationRequest(fileName)
        requestBody.put("validationLevel", "ArchivalData")

        when: "request is sent with ArchivalData validation level"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature validation fails"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(indication))
                .body("validationLevel", is("ARCHIVAL_DATA"))
                .body("signatures[0].errors.content", hasItem(TS_MESSAGE_NOT_INTACT))
                .body("signatures[0].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                                      | fileName                                       || indication
        "TS certificate expired"                         | "TEST_XAdES_LTA.xml"                           || "TOTAL-FAILED"
        "TS/OCSP certificates expired"                   | "TEST_XAdES_LTA-AiaOcsp-Expired-202308.xml"    || "TOTAL-FAILED"
        "all certificates expired"                       | "3_signatures_TM_LT_LTA.xml"                   || "TOTAL-FAILED"
        "signed with expired OCSP"                       | "esteid2018signerAiaOcspExpiredLTA.xml"        || "INDETERMINATE"
        "not trusted ATS"                                | "2xLTA-SK+Entrust.xml"                         || "TOTAL-FAILED"
        "multiple ATS"                                   | "TEST_XAdES_LTA-2xArchivetimestamps.xml"       || "TOTAL-FAILED"
        "Qualified TS + Not-qualified ATS"               | "LTA_QTSA_TSA.xml"                             || "TOTAL-FAILED"
        "Qualified TS + Not-qualified and Qualified ATS" | "LTA_QTSA_TSA_QTSA.xml"                        || "TOTAL-FAILED"
        "Not-qualified TS + Qualified ATS"               | "LTA_TSA_QTSA.xml"                             || "TOTAL-FAILED"
        "TS replaced"                                    | "TEST_XAdES_LTA-Ts-Replaced.xml"               || "TOTAL-FAILED"
        "ATS replaced"                                   | "TEST_XAdES_LTA-Archivetimestamp-Replaced.xml" || "TOTAL-FAILED"
    }

    @Story("Validate LTA hashcode with validation level set")
    def "Validate LTA hashcode succeeds with LongTermData validation level with #description"() {
        given: "validation level is set to LongTermData"
        Map requestBody = RequestData.hashcodeValidationRequest(fileName)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent with LongTermData validation level"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature validation succeeds"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].errors[0].content", emptyOrNullString())
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                                      | fileName
        "TS certificate expired"                         | "TEST_XAdES_LTA.xml"
        "TS/OCSP certificates expired"                   | "TEST_XAdES_LTA-AiaOcsp-Expired-202308.xml"
        "all certificates expired"                       | "3_signatures_TM_LT_LTA.xml"
        "not trusted ATS"                                | "2xLTA-SK+Entrust.xml"
        "multiple ATS"                                   | "TEST_XAdES_LTA-2xArchivetimestamps.xml"
        "Qualified TS + Not-qualified ATS"               | "LTA_QTSA_TSA.xml"
        "Qualified TS + Not-qualified and Qualified ATS" | "LTA_QTSA_TSA_QTSA.xml"
        "ATS replaced"                                   | "TEST_XAdES_LTA-Archivetimestamp-Replaced.xml"
    }

    @Story("Validate LTA hashcode with validation level set")
    def "Validate LTA hashcode fails with LongTermData validation level if #description"() {
        given: "validation level is set to LongTermData"
        Map requestBody = RequestData.hashcodeValidationRequest(fileName)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent with LongTermData validation level"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature is not valid"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(indication))
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                        | fileName                                || indication
        "signed with expired OCSP"         | "esteid2018signerAiaOcspExpiredLTA.xml" || "INDETERMINATE"
        "Not-qualified TS + Qualified ATS" | "LTA_TSA_QTSA.xml"                      || "TOTAL-FAILED"
        "TS replaced"                      | "TEST_XAdES_LTA-Ts-Replaced.xml"        || "TOTAL-FAILED"
    }

    @Story("ATS no effect warning not produced for not-LTA hashcode signature")
    def "Validate #description hashcode with LongTermData validation level: LTA warning is not reported"() {
        given: "not-LTA signatures validation level is set to LongTermData"
        Map requestBody = RequestData.hashcodeValidationRequest(fileName)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature has no ATS warning"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))

        where:
        description | fileName                                || signatureFormat
        "B-level"   | "TEST_ESTEID2018_XAdES_B_detached.xml"  || SignatureFormat.XAdES_BASELINE_B
        "T-level"   | "TEST_ESTEID2018_XAdES_T_detached.xml"  || SignatureFormat.XAdES_BASELINE_T
        "LT-level"  | "TEST_ESTEID2018_XAdES_LT_detached.xml" || SignatureFormat.XAdES_BASELINE_LT
    }

    @Story("ATS no effect warning not produced for not-LTA hashcode signature")
    def "When validating LTA and LT hashcode with LongTermData validation level, then ATS warning added only to LTA"() {
        given: "request with LTA and LT signature files and LongTermData validation level"
        Map requestBody = RequestData.hashcodeValidationRequest(["TEST_XAdES_LTA.xml", "Valid_XAdES_LT_TS.xml"], null, null)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "ATS warning is reported for the LTA signature only"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signaturesCount", is(2))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))
    }

    @Story("Validation level has no effect on signature without archive timestamp")
    def "When validating LT hashcode with #validationLevel validation level the result does not change"() {
        given: "validation level is set"
        Map requestBody = RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS.xml")
        requestBody.put("validationLevel", validationLevel)

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "validation result is the same for both validation levels"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validationLevel", is(reportedLevel))
                .body("signaturesCount", is(1))

        where:
        validationLevel | reportedLevel
        "ArchivalData"  | "ARCHIVAL_DATA"
        "LongTermData"  | "LONG_TERM_DATA"
    }

}
