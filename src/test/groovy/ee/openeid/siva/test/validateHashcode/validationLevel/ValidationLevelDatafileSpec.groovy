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

package ee.openeid.siva.test.validateHashcode.validationLevel

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Epic("Signature validation (hashcode)")
@Feature("Validation level validation with datafile hashes")
@Link("https://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface-for-hashcode")
class ValidationLevelDatafileSpec extends GenericSpecification {

    static final String LTA_DATAFILE_NAME = "test.txt"
    static final String LTA_DATAFILE_SHA256 = "f58hd1VwCI0MX2+2hPsZDmiK1OiUFJnLo2XhU4NykmI="
    static final String LTA_DATAFILE_SHA512 = "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w=="

    @Story("Validate LTA hashcode with datafile hash and validation level set")
    def "Validate LTA hashcode with datafile hash succeeds with LongTermData validation level: #description"() {
        given: "request with datafile hash and LongTermData validation level"
        Map requestBody = RequestData.hashcodeValidationRequest(fileName, null, null, LTA_DATAFILE_NAME, hashAlgo, hash)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature is valid and ATS warning is reported"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", anyOf(nullValue(), empty()))
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))
                .body("signatures[0].info.archiveTimeStamps.indication", hasItem("FAILED"))
                .body("validSignaturesCount", is(1))

        where:
        description                        | fileName                                 | hashAlgo        | hash
        "TS certificate expired"           | "TEST_XAdES_LTA.xml"                     | HashAlgo.SHA256 | LTA_DATAFILE_SHA256
        "Qualified TS + Not-qualified ATS" | "LTA_QTSA_TSA.xml"                       | HashAlgo.SHA256 | LTA_DATAFILE_SHA256
        "multiple ATS, SHA512 reference"   | "TEST_XAdES_LTA-2xArchivetimestamps.xml" | HashAlgo.SHA512 | LTA_DATAFILE_SHA512
    }

    @Story("Validate LTA hashcode with datafile hash and validation level set")
    def "Validate LTA hashcode with datafile hash fails with ArchivalData validation level"() {
        given: "request with datafile hash and ArchivalData validation level"
        Map requestBody = RequestData.hashcodeValidationRequest("TEST_XAdES_LTA.xml", null, null, LTA_DATAFILE_NAME, HashAlgo.SHA256, LTA_DATAFILE_SHA256)
        requestBody.put("validationLevel", "ArchivalData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature is not valid and no ATS warning is reported"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("ARCHIVAL_DATA"))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItem(TS_MESSAGE_NOT_INTACT))
                .body("signatures[0].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))
                .body("validSignaturesCount", is(0))
    }

    @Story("LongTermData validation level does not hide datafile errors")
    def "Validate LTA hashcode with LongTermData validation level fails if #description"() {
        given: "request with mismatching datafile and LongTermData validation level"
        Map requestBody = RequestData.hashcodeValidationRequest("TEST_XAdES_LTA.xml", null, null, dataFileName, HashAlgo.SHA256, hash)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "signature is not valid"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].indication", is(indication))
                .body("signatures[0].subIndication", is(subIndication))
                .body("signatures[0].errors.content", hasItem(error))
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))
                .body("validSignaturesCount", is(0))

        where:
        description              | dataFileName      | hash                || indication      | subIndication           | error
        "datafile hash is wrong" | LTA_DATAFILE_NAME | LTA_DATAFILE_SHA512 || "TOTAL-FAILED"  | "HASH_FAILURE"          | REFERENCE_DATA_NOT_INTACT
        "datafile name is wrong" | "wrong.txt"       | LTA_DATAFILE_SHA256 || "INDETERMINATE" | "SIGNED_DATA_NOT_FOUND" | REFERENCE_NAME_DOES_NOT_MATCH
    }

    @Story("Validation level is applied regardless of report type")
    def "Validate LTA hashcode with LongTermData validation level and #reportType report type"() {
        given: "request with LongTermData validation level and report type"
        Map requestBody = RequestData.hashcodeValidationRequest("TEST_XAdES_LTA.xml", null, reportType)
        requestBody.put("validationLevel", "LongTermData")

        when: "request is sent"
        Response response = SivaRequests.validateHashcode(requestBody)

        then: "simple report with LongTermData validation level is returned"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationLevel", is("LONG_TERM_DATA"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].warnings.content", hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA))

        where:
        reportType << [ReportType.SIMPLE, ReportType.DETAILED, ReportType.DIAGNOSTIC]
    }
}
