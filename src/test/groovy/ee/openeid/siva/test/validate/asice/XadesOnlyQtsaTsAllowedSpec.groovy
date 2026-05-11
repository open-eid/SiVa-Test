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

package ee.openeid.siva.test.validate.asice

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
@Feature("ASiC-E validation")
@Story("Only QTSA timestamp allowed")
@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class XadesOnlyQtsaTsAllowedSpec extends GenericSpecification {

    def "ASiC-E LT signature with QTSA timestamp passes: #description"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(testfile))

        then: "signature passes with QTSA timestamp"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is(timestamp))

        where:
        description                                          | testfile                       | timestamp
        "QTSA level present in TSL before eIDAS"             | "singleValidSignatureTS.asice" | "DEMO of SK TSA 2014"
        "QTSA level, but withdrawn during validation in TSL" | "EE_SER-AEX-B-LT-V-30.asice"   | "SK TIMESTAMPING AUTHORITY"
//TODO: SIVA-796 "QTSA level during signing, before was non-qualified in TSL" | "< testfile needed >"          | ""
    }

    def "ASiC-E LTA signature with QTSA signature timestamp and QTSA archive timestamp passes"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce"))

        then: "signature passes with QTSA signature and archive timestamps"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("signatures[0].info.archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("signatures[0].info.archiveTimeStamps[0].indication", is("PASSED"))
    }

    def "ASiC-E LTA signature with #description fails"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(testfile))

        then: "signature fails with non-qualified timestamp error"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].info.archiveTimeStamps.findAll{it.indication != 'PASSED'}.subIndication", everyItem(is("NO_CERTIFICATE_CHAIN_FOUND")))
                .body("signatures[0].errors.content", containsInAnyOrder(CERT_NOT_RELATED_TO_TSA_QTST, CERT_NOT_RELATED_TO_EXPECTED_IDENTIFIER))
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
