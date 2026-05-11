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

package ee.openeid.siva.test.validate.bdoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Epic("Signature validation (datafile)")
@Feature("BDOC validation")
@Story("Only QTSA timestamp allowed")
@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class BdocOnlyQtsaTsAllowedSpec extends GenericSpecification {

    def "ASiC-E LT signature via DD4J validator with non-qualified signature timestamp fails"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequestForDD4J("LT_TSA.asice"))

        then: "signature fails with non-qualified timestamp error"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", containsInAnyOrder(CERT_NOT_RELATED_TO_TSA_QTST, CERT_NOT_RELATED_TO_EXPECTED_IDENTIFIER, SIG_INVALID_TS))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("Entrust Timestamp Authority - TSA1"))
    }

    def "ASiC-E LTA signature via DD4J validator with #description fails"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequestForDD4J(testfile))

        then: "signature fails with non-qualified timestamp error"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", containsInAnyOrder((timestamp == "Entrust Timestamp Authority - TSA1"
                        ? [CERT_NOT_RELATED_TO_TSA_QTST, CERT_NOT_RELATED_TO_EXPECTED_IDENTIFIER, SIG_INVALID_TS]
                        : [CERT_NOT_RELATED_TO_TSA_QTST, CERT_NOT_RELATED_TO_EXPECTED_IDENTIFIER]) as String[]))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is(timestamp))
                .body("signatures[0].info.archiveTimeStamps.signedBy", is(archiveTS))
                .body("signatures[0].info.archiveTimeStamps.indication", is(archiveIndications))

        where:
        description                                                      | testfile                  | timestamp                              | archiveTS                                                                      | archiveIndications
        "QTSA signature TS + non-qualified archive TS"                   | "LTA_QTSA_TSA.asice"      | "DEMO SK TIMESTAMPING AUTHORITY 2023E" | ["Entrust Timestamp Authority - TSA1"]                                         | [INDETERMINATE]
        "QTSA signature TS + QTSA archive TS + non-qualified archive TS" | "2xLTA-SK+Entrust.asice"  | "DEMO SK TIMESTAMPING UNIT 2025E"      | ["DEMO SK TIMESTAMPING UNIT 2025E", "Entrust Timestamp Authority - TSA1"]      | [VALID_INDICATION_VALUE_PASSED, INDETERMINATE]
        "QTSA signature TS + non-qualified archive TS + QTSA archive TS" | "LTA_QTSA_TSA_QTSA.asice" | "DEMO SK TIMESTAMPING AUTHORITY 2023E" | ["Entrust Timestamp Authority - TSA1", "DEMO SK TIMESTAMPING AUTHORITY 2023E"] | [INDETERMINATE, VALID_INDICATION_VALUE_PASSED]
        "non-qualified signature TS + QTSA archive TS"                   | "LTA_TSA_QTSA.asice"      | "Entrust Timestamp Authority - TSA1"   | ["DEMO SK TIMESTAMPING AUTHORITY 2023E"]                                       | [VALID_INDICATION_VALUE_PASSED]
    }
}
