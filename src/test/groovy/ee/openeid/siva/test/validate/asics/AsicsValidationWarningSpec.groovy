package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.DssMessage
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.TimestampLevel
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description

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

    @Description("Validation of timestamps not in 'granted' state in TSL")
    def "Given ASiC-S with single withdrawn timestamp, then validation returns warnings"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DdocInAsicsWithdrawnTS.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("timeStampTokens[0].warning", hasSize(1))
                .body("timeStampTokens[0].warning.content", hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message))
                .body("timeStampTokens[0].timestampLevel", is(TimestampLevel.TSA))
                .body("validatedDocument.filename", is("DdocInAsicsWithdrawnTS.asics"))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.NOT_GRANTED_CONTAINER_WARNING))
    }

    @Description("Validation of timestamps not in 'granted' state in TSL")
    def "Given ASiC-S with multiple timestamps, when one withdrawn, then validation returns warnings"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DdocInAsicsWithdrawnTsOverStamped.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("timeStampTokens[0].warning", hasSize(1))
                .body("timeStampTokens[0].warning.content", hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message))
                .body("timeStampTokens[0].timestampLevel", is(TimestampLevel.TSA))
                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[1].signedBy", is("SK TIMESTAMPING UNIT 2025E"))
                .body("timeStampTokens[1].signedTime", is("2025-04-09T14:59:22Z"))
                .body("timeStampTokens[1].warning", emptyOrNullString())
                .body("timeStampTokens[1].timestampLevel", is(TimestampLevel.QTSA))
                .body("validatedDocument.filename", is("DdocInAsicsWithdrawnTsOverStamped.asics"))
        // SIVA-760: Currently we don't differentiate if container contains just withdrawn timestamps
        // or the container has already been stamped over with a timestamp in granted state in TSL.
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.NOT_GRANTED_CONTAINER_WARNING))
    }
}
