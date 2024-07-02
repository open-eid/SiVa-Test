package ee.openid.siva.test


import static io.restassured.RestAssured.given

class SoapEndpointsDeprecatedSpec extends GenericSpecification {

    /**
     * TestCaseID: Soap-Endpoints-Deprecated
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface
     *
     * Title: Soap endpoints deprecated
     *
     * Expected Result: 404 Not Found
     */
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
