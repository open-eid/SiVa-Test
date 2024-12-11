package ee.openeid.siva.test.validate.asice

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response

import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class XadesLtaValidationFailSpec extends GenericSpecification {

    @Description("Asice Baseline-LTA file")
    def "Given invalid XAdES LTA signature with non-qualified timestamp present, then simple report has correct warnings/errors"() {
        when: "report is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LTA-V-24.asice"))

        then: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("EE_SER-AEX-B-LTA-V-24Report.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)
    }
}
