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


package ee.openeid.siva.test.validate

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.getLTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA
import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.not

@Epic("Signature validation (datafile)")
@Feature("XAdES LTA datafile validation")
@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class LtaValidationSpec extends GenericSpecification {

    @Story("LTA archive timestamp warning is not reported for datafile validation")
    def "In datafile flow validating XAdES LTA signature does not produce LONG_TERM_DATA warning"() {
        when: "request is sent"
        Response response = SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce"))

        then: "LONG_TERM_DATA warning is absent"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].warnings.content", not(hasItem(LTA_ATS_NO_EFFECT_AT_LONG_TERM_DATA)))
    }
}
