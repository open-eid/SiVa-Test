package ee.openeid.siva.test

import ee.openeid.siva.test.allure.SivaRequirement

import static io.restassured.RestAssured.given

class SoapEndpointsDeprecatedSpec extends GenericSpecification {

    @SivaRequirement("interfaces")
    def "Soap #endpoint endpoint deprecated"() {
        given:
        String sivaServiceUrl = "${conf.sivaProtocol()}://${conf.sivaHostname()}:${conf.sivaPort()}${conf.sivaContextPath()}"

        expect:
        given()
                .contentType("text/xml;charset=UTF-8")
                .body("<test></test>")
                .when()
                .post(sivaServiceUrl + "/soap/" + endpoint)
                .then()
                .statusCode(404)

        where:
        endpoint                       | _
        "validationWebService"         | _
        "hashcodeValidationWebService" | _
        "dataFilesWebService"          | _
    }
}
