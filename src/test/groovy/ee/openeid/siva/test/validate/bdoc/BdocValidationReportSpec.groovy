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

package ee.openeid.siva.test.validate.bdoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

@Epic("BDOC")
@Feature("Validation report verification")
class BdocValidationReportSpec extends GenericSpecification {

    @Story("BDOC XAdES_BASELINE_LT_TM validation report matches JSON structure and has expected values")
    def "BDOC with one valid LT-TM signature has correct validation report values present"() {
        when: "report is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("singleValidSignatureTM.bdoc",
                SignaturePolicy.POLICY_3))

        then: "report matches JSON structure"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))

        and: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("singleValidSignatureTM.bdoc.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)
    }

    @Story("BDOC XAdES_BASELINE_LT_TM validation report matches JSON structure and has expected values")
    def "BDOC with multiple valid signatures have correct validation report values present"() {
        when:
        Response response = SivaRequests.validate(RequestData.validationRequest("Baltic MoU digital signing_EST_LT_LV.bdoc",
                SignaturePolicy.POLICY_3))

        then: "report matches JSON structure"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))

        and: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("Baltic MoU digital signing_EST_LT_LV.bdoc.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)
    }

    @Story("Simple report includes timestamp creation time for timestamped signature")
    def "Given BDOC with timestamped signature, then validation report includes timestampCreationTime field"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file, "bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[0].info.timestampCreationTime", is(timestampCreationTime))

        where:
        file                                   | timestampCreationTime
        "TEST_ESTEID2018_ASiC-E_XAdES_T.sce"   | "2024-09-13T14:14:24Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"  | "2024-09-13T14:14:36Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce" | "2024-09-13T14:14:47Z"
    }

    @Story("Simple report includes timestamp creation time for timestamped signature")
    def "Given BDOC with multiple timestamped signatures, then validation report includes timestampCreationTime field for each"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.sce", "bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[1].info.timestampCreationTime", is("2021-01-29T14:31:36Z"))
                .body("signatures[2].info.timestampCreationTime", is("2021-01-29T14:38:11Z"))
    }

    @Story("Simple report includes archive timestamp info")
    def "Given BDOC with archive timestamped signature, then archiveTimeStamps info is reported correctly"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.bdoc")).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(TestData.VALIDATION_CONCLUSION_PREFIX + "signatures[2].info")
                .body("archiveTimeStamps.size()", is(1))

                .body("archiveTimeStamps[0].signedTime", is("2021-01-29T14:38:11Z"))
                .body("archiveTimeStamps[0].country", is("EE"))
                .body("archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING AUTHORITY 2020"))
                .body("archiveTimeStamps[0].indication", is("PASSED"))
                .body("archiveTimeStamps[0].content", is("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"))
    }
}
