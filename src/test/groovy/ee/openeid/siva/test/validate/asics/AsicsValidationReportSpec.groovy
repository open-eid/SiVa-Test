package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.restassured.response.Response
import org.junit.Ignore
import spock.lang.Tag

import static ee.openeid.siva.test.TestData.SUB_INDICATION_SIG_CRYPTO_FAILURE
import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import static org.hamcrest.Matchers.containsInAnyOrder
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class AsicsValidationReportSpec extends GenericSpecification {

    @Description("Timestamped ASiC-S report matches JSON structure and has expected values")
    def "Given #description, then simple report has correct values present"() {
        when: "report is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("${filename}.asics"))

        then: "report matches JSON structure"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))

        and: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("${filename}Report.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)

        where:
        filename                       | description
        "ValidAsics"                   | "text file in timestamped ASiC-S"
        "Valid2xTstAsics"              | "text file in double timestamped ASiC-S"
        "ValidTimestampedAsicsInAsics" | "timestamped ASiC-S (nested) in timestamped ASiC-S"
        "Valid2xNestedAsics"           | "2x nested ASiC-S"
        "ValidSignedAsicsInAsics"      | "signed ASiC-S in timestamped ASiC-S"
        "ValidAsiceInAsics"            | "ASiC-E in timestamped ASiC-S"
        "ValidBdocInAsics"             | "BDOC in timestamped ASiC-S"
        "ValidDdocInAsics"             | "DDOC in timestamped ASiC-S"
    }

    @Ignore("SIVA-778")
    @Tag("slow")
    @Description("Timestamped ASiC-S report matches JSON structure and has expected values")
    def "Given 200x timestamped ASiC-S, then simple report has correct values present"() {
        when: "report is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("Valid200xTstAsics.asics"))

        then: "report matches JSON structure"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))

        and: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("Valid200xTstAsicsReport.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)
    }

    @Description("Invalid timestamped ASiC-S report matches JSON structure and has expected values")
    def "Given invalid timestamped ASiC-S, then simple report has correct values present"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("1xTST-valid-bdoc-data-file-invalid-signature-in-tst.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("timeStampTokens[0].indication", equalTo(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[0].subIndication", equalTo(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("timeStampTokens[0].error.findAll{it.content}.content", containsInAnyOrder(
                        "The signature is not intact!",
                        "The encryption algorithm ? is not authorised for time-stamp signature!"))
    }

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given ASiC-S with timestamped signature, then validation report includes timestampCreationTime field"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_S))
                .body("signatures[0].info.timestampCreationTime", is(timestampCreationTime))

        where:
        file                                   | timestampCreationTime
        "TEST_ESTEID2018_ASiC-S_XAdES_T.scs"   | "2024-09-13T14:11:57Z"
        "TEST_ESTEID2018_ASiC-S_XAdES_LT.scs"  | "2024-09-13T14:12:12Z"
        "TEST_ESTEID2018_ASiC-S_XAdES_LTA.scs" | "2024-09-13T14:12:25Z"
        "TEST_ESTEID2018_ASiC-S_CAdES_T.scs"   | "2024-09-13T14:12:55Z"
        "TEST_ESTEID2018_ASiC-S_CAdES_LT.scs"  | "2024-09-13T14:13:06Z"
        "TEST_ESTEID2018_ASiC-S_CAdES_LTA.scs" | "2024-09-13T14:13:19Z"
    }
}
