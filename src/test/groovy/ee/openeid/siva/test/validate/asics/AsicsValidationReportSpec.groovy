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
import static org.hamcrest.Matchers.*

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

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-S with archive timestamped signature, then validation report includes archiveTimeStamps object"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file)).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.findAll { it.signatureFormat.contains('LTA') }.info",
                        everyItem(hasKey("archiveTimeStamps")))
                .body("signatures.findAll { !it.signatureFormat.contains('LTA') }.info",
                        everyItem(not(hasKey("archiveTimeStamps"))))

        where:
        file                                   | _
        "TEST_ESTEID2018_ASiC-S_XAdES_LTA.scs" | _
        "TEST_ESTEID2018_ASiC-S_CAdES_LTA.scs" | _
    }

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-S with archive timestamped signature, then archiveTimeStamps info is reported correctly"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-S_XAdES_LTA.scs")).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX + "signatures[0].info")
                .body("archiveTimeStamps.size()", is(1))

                .body("archiveTimeStamps[0].signedTime", is("2024-09-13T14:12:25Z"))
                .body("archiveTimeStamps[0].country", is("EE"))
                .body("archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("archiveTimeStamps[0].indication", is("PASSED"))
                .body("archiveTimeStamps[0].content", is("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"))
    }
}
