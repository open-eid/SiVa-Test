package ee.openeid.siva.test.validate.bdoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description

import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.is

class BdocValidationReportSpec extends GenericSpecification {

    @Description("Simple report includes timestamp creation time for timestamped signature")
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

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given BDOC with multiple timestamped signatures, then validation report includes timestampCreationTime field for each"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.sce", "bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[1].info.timestampCreationTime", is("2021-01-29T14:31:36Z"))
                .body("signatures[2].info.timestampCreationTime", is("2021-01-29T14:38:11Z"))
    }
}
