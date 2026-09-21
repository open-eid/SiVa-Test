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
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.getTS_MESSAGE_NOT_INTACT
import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Epic("Signature validation (hashcode)")
@Feature("XAdES LTA hashcode validation")
@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class XadesHashcodeLtaValidationSpec extends GenericSpecification {

    @Ignore("SIVA-1206")
    @Story("Validate LTA hashcode with default settings")
    def "Validate LTA hashcode fails without setting validation level: #description"() {
        when: "request is sent without validation level"
        Response response = SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest(fileName))

        then: "signature validation fails"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(indication))
                .body("signatures[0].errors.content", hasItem(TS_MESSAGE_NOT_INTACT))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                                      | fileName                                       || indication
        "TS certificate expired"                         | "TEST_XAdES_LTA.xml"                           || "TOTAL-FAILED"
        "TS/OCSP certificates expired"                   | "TEST_XAdES_LTA-AiaOcsp-Expired-202308.xml"    || "TOTAL-FAILED"
        "all certificates expired"                       | "3_signatures_TM_LT_LTA.xml"                   || "TOTAL-FAILED"
        "OCSP not trusted"                               | "esteid2018signerAiaOcspExpiredLTA.xml"        || "INDETERMINATE"
        "not trusted ATS"                                | "2xLTA-SK+Entrust.xml"                         || "TOTAL-FAILED"
        "multiple ATS"                                   | "TEST_XAdES_LTA-2xArchivetimestamps.xml"       || "TOTAL-FAILED"
        "Qualified TS + Not-qualified ATS"               | "LTA_QTSA_TSA.xml"                             || "TOTAL-FAILED"
        "Qualified TS + Not-qualified and Qualified ATS" | "LTA_QTSA_TSA_QTSA.xml"                        || "TOTAL-FAILED"
        "Not-qualified TS + Qualified ATS"               | "LTA_TSA_QTSA.xml"                             || "TOTAL-FAILED"
        "TS replaced"                                    | "TEST_XAdES_LTA-Ts-Replaced.xml"               || "TOTAL-FAILED"
        "ATS replaced"                                   | "TEST_XAdES_LTA-Archivetimestamp-Replaced.xml" || "TOTAL-FAILED"
    }

    @Ignore("SIVA-1206")
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
                .body("signatures[0].errors.content", hasItem(TS_MESSAGE_NOT_INTACT))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                                      | fileName                                       || indication
        "TS certificate expired"                         | "TEST_XAdES_LTA.xml"                           || "TOTAL-FAILED"
        "TS/OCSP certificates expired"                   | "TEST_XAdES_LTA-AiaOcsp-Expired-202308.xml"    || "TOTAL-FAILED"
        "all certificates expired"                       | "3_signatures_TM_LT_LTA.xml"                   || "TOTAL-FAILED"
        "OCSP not trusted"                               | "esteid2018signerAiaOcspExpiredLTA.xml"        || "INDETERMINATE"
        "not trusted ATS"                                | "2xLTA-SK+Entrust.xml"                         || "TOTAL-FAILED"
        "multiple ATS"                                   | "TEST_XAdES_LTA-2xArchivetimestamps.xml"       || "TOTAL-FAILED"
        "Qualified TS + Not-qualified ATS"               | "LTA_QTSA_TSA.xml"                             || "TOTAL-FAILED"
        "Qualified TS + Not-qualified and Qualified ATS" | "LTA_QTSA_TSA_QTSA.xml"                        || "TOTAL-FAILED"
        "Not-qualified TS + Qualified ATS"               | "LTA_TSA_QTSA.xml"                             || "TOTAL-FAILED"
        "TS replaced"                                    | "TEST_XAdES_LTA-Ts-Replaced.xml"               || "TOTAL-FAILED"
        "ATS replaced"                                   | "TEST_XAdES_LTA-Archivetimestamp-Replaced.xml" || "TOTAL-FAILED"
    }

    @Ignore("SIVA-1206")
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
                .body("signatures[0].errors[0].content", emptyOrNullString())
                .body("signatures[0].warnings[0].content", emptyOrNullString())
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

    @Ignore("SIVA-1206")
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
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

                .body("signatures[0].info.archiveTimeStamps[0].indication", is("FAILED"))
                .body("signatures[0].info.archiveTimeStamps[0].subIndication", is("HASH_FAILURE"))

        where:
        description                        | fileName                                || indication
        "OCSP not trusted"                 | "esteid2018signerAiaOcspExpiredLTA.xml" || "INDETERMINATE"
        "Not-qualified TS + Qualified ATS" | "LTA_TSA_QTSA.xml"                      || "TOTAL-FAILED"
        "TS replaced"                      | "TEST_XAdES_LTA-Ts-Replaced.xml"        || "TOTAL-FAILED"
    }

}
