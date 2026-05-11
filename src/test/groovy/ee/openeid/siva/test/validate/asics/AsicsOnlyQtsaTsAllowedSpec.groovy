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

package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.getNOT_GRANTED_CONTAINER_WARNING
import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Epic("Signature validation (datafile)")
@Feature("ASiC-S validation")
@Story("Only QTSA timestamp allowed")
@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class AsicsOnlyQtsaTsAllowedSpec extends GenericSpecification {

    def "ASiC-S with QTSA timestamp passes: #description"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(testfile))

        then: "timestamps pass with QTSA level"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("timeStampTokens.size()", is(timestampCount))
                .body("timeStampTokens.indication", everyItem(is(SignatureIndication.TOTAL_PASSED)))
                .body("timeStampTokens.signedBy", everyItem(is("DEMO SK TIMESTAMPING AUTHORITY 2023E")))
                .body("timeStampTokens.timestampLevel", everyItem(is(TimestampLevel.QTSA)))
                .body("timeStampTokens.findAll{it.warning}.warning", empty())

        where:
        description                | testfile                | timestampCount
        "single QTSA timestamp"    | "ValidAsics.asics"      | 1
        "multiple QTSA timestamps" | "Valid2xTstAsics.asics" | 2
    }

    def "ASiC-S with single withdrawn timestamp returns warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("DdocInAsicsWithdrawnTS.asics"))

        then: "withdrawn timestamp returns warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("timeStampTokens.indication", everyItem(is(SignatureIndication.TOTAL_PASSED)))
                .body("timeStampTokens.signedBy", everyItem(is("SK TIMESTAMPING AUTHORITY")))
                .body("timeStampTokens[0].timestampLevel", is(TimestampLevel.TSA))
                .body("timeStampTokens[0].warning.content", hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message))
                .body("validationWarnings.content", hasItem(NOT_GRANTED_CONTAINER_WARNING))
    }

    def "ASiC-S with multiple timestamps and one withdrawn returns warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("DdocInAsicsWithdrawnTsOverStamped.asics"))

        then: "withdrawn timestamp returns warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("timeStampTokens.indication", everyItem(is(SignatureIndication.TOTAL_PASSED)))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].timestampLevel", is(TimestampLevel.TSA))
                .body("timeStampTokens[0].warning.content", hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message))
                .body("timeStampTokens[1].signedBy", is("SK TIMESTAMPING UNIT 2025E"))
                .body("timeStampTokens[1].timestampLevel", is(TimestampLevel.QTSA))
        // SIVA-760: Currently we don't differentiate if container contains just withdrawn timestamps
        // or the container has already been stamped over with a timestamp in granted state in TSL.
                .body("validationWarnings.content", hasItem(NOT_GRANTED_CONTAINER_WARNING))
    }

    def "ASiC-S with #description fails"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(testfile))

        then: "non-qualified timestamp fails"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("timeStampTokens.indication", is(indications))
                .body("timeStampTokens.signedBy", is(signedBy))
                .body("timeStampTokens.timestampLevel", is(levels))

        where:
        description                   | testfile                 | indications                                                          | signedBy                                                                  | levels
        "single non-qualified TSA TS" | "TSA.asics"              | [SignatureIndication.TOTAL_FAILED]                                   | ["Entrust Timestamp Authority - TSA1"]                                    | [TimestampLevel.TSA]
        "QTSA TS + non-qualified TS"  | "2xTst-SK+Entrust.asics" | [SignatureIndication.TOTAL_PASSED, SignatureIndication.TOTAL_FAILED] | ["DEMO SK TIMESTAMPING UNIT 2025E", "Entrust Timestamp Authority - TSA1"] | [TimestampLevel.QTSA, TimestampLevel.TSA]
        "non-qualified TS + QTSA TS"  | "2xTst-Entrust+SK.asics" | [SignatureIndication.TOTAL_FAILED, SignatureIndication.TOTAL_PASSED] | ["Entrust Timestamp Authority - TSA1", "DEMO SK TIMESTAMPING UNIT 2025E"] | [TimestampLevel.TSA, TimestampLevel.QTSA]
    }
}
