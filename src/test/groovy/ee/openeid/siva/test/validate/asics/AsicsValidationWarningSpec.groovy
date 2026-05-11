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

package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Story

import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

class AsicsValidationWarningSpec extends GenericSpecification {

    @Description("Validation of ASiC-S with timestamp not covering datafile/nested container")
    def "Validating ASiC-S with timestamp not covering #targetFile, then warning is returned#comment"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is(fileName))
                .body("signaturesCount", is(0))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[1].warning.size()", is(1))
                .body("timeStampTokens[1].warning[0].content", is("The time-stamp token does not cover container datafile!"))
                .body('$', not(hasKey("signatures")))
                .body("timeStampTokens.collectMany{it.timestampScopes.findAll{it.scope=='ARCHIVED'}.name}", is(empty()))

        where:
        fileName                                                         | targetFile                 || comment
        "2xTstFirstInvalidSecondNotCoveringDatafile.asics"               | "datafile"                 || ""
        "2xTstFirstInvalidSecondNotCoveringNestedTimestampedAsics.asics" | "nested timestamped asics" || " and nested container is not validated"
        "2xTstFirstInvalidSecondNotCoveringNestedSignedAsics.asics"      | "nested signed asics"      || " and nested container is not validated"
        "2xTstFirstInvalidSecondNotCoveringNestedSignedAsice.asics"      | "nested signed asice"      || " and nested container is not validated"
    }

}
