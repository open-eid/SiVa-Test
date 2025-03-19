/*
 * Copyright 2024 - 2025 Riigi Infosüsteemi Amet
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
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/overview/#main-features-of-siva-validation-service")
class MimetypeValidationSpec extends GenericSpecification {

    @Description("ASICe container with valid mimetype.")
    def "asiceValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerValidMimetype.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings.content", hasItem(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid ASICe container with mimetype as last in cointainer.")
    def "asiceInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeAsLast.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container with deflated mimetype.")
    def "asiceInvalidMimetypeCompressionAsDeflated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeIsDeflated.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid ASICe container without mimetype.")
    def "asiceWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerNoMimetype.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container mimetype filename with capital letter (Mimetype).")
    def "asiceMimetypeFileNameWithCapitalLetter"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeWithCapitalLetter.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "asiceMimetypeFilenameWithExtraSpace"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeFilenameWithExtraSpace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container with extra byte in the beginning of the container.")
    def "asiceContainerWithExtraByteInBeginning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeWithCapitalLetter.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("ASICe container with invalid mimetype as \"text/plain\".")
    def "asiceInvalidMimetypeAsText"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceInvalidMimetypeAsText.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_INVALID_TYPE))
    }

    @Description("BDOC container with valid mimetype.")
    def "bdocValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerValidMimetype.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings.content", hasItem(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid BDOC container with mimetype as last.")
    def "bdocInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerMimetypeAsLast.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid BDOC container with deflated mimetype.")
    def "bdocInvalidMimetypeCompressionAsDeflated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerMimetypeIsDeflated.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid BDOC container without mimetype.")
    def "bdocWithNoMimetype"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("BdocContainerNoMimetype.bdoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Invalid BDOC container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "bdocMimetypeFilenameWithExtraSpace"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("BdocContainerMimetypeFilenameWithExtraSpace.bdoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("BDOC container with invalid mimetype as \"application/zip\".")
    def "bdocInvalidMimetypeAsZip"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("BdocInvalidMimetypeAsZip.bdoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("ASICs container with valid mimetype and Tmp file inside.")
    def "asicsValidMimetypeWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerValidMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings.content", hasItem(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    // SIVA-761 needs a new container
    @Description("ASICs container with valid mimetype and DDOC inside.")
    def "asicsValidMimetypeWithDdocContainer"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerValidMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2)) // SIVA-761: 2->1
                .body("validationWarnings.content", hasItem(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid ASICs container with mimetype as last and Tmp file inside.")
    def "asicsInvalidMimetypeLocationAsLastWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeAsLast.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    // SIVA-761 needs a new container
    @Description("Invalid ASICs container with mimetype as last and DDOC inside.")
    def "asicsInvalidMimetypeLocationAsLastWithDdoc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerMimetypeAsLast.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(3)) // SIVA-761: 3->2
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container with deflated mimetype and Tmp file inside.")
    def "asicsInvalidMimetypeCompressionAsDeflatedWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeIsDeflated.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_COMPRESSED_WARNING))
    }

    // SIVA-761 needs a new container
    @Description("Invalid ASICs container with deflated mimetype and DDOC inside.")
    def "asicsInvalidMimetypeCompressionAsDeflatedWithDdoc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerMimetypeIsDeflated.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(3)) // SIVA-761: 3->2
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid ASICs container without mimetype and Tmp file inside.")
    def "asicsContainingTmpFileWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerNoMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    // SIVA-761 needs a new container
    @Description("Invalid ASICs container without mimetype and DDOC inside.")
    def "asicsContainingDdocContainerWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerNoMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(3)) // SIVA-761: 3->2
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "asicsMimetypeFilenameWithExtraSpace"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeFilenameWithExtraSpace.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
                .body("signatures[0].errors.content", hasItem("The manifest file is absent!"))
    }

    @Description("ASICs container with invalid mimetype as \"application/xml\".")
    def "asicsInvalidMimetypeAsXml"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsInvalidMimetypeAsXml.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_INVALID_TYPE))
    }

    @Description("Valid EDOC container with valid.")
    def "edocValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerValidMimetype.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings.content", hasItem(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid EDOC container with mimetype as last in cointainer.")
    def "edocInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerValidMimetypeAsLast.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid EDOC container without mimetype.")
    def "edocWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerNoMimetype.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Valid ADOC container with mimetype.")
    def "adocMimetypeWithExtraFields"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AdocContainerMimetypeWithExtraFields.adoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings.content", hasItem(TestData.MIMETYPE_EXTRA_FIELDS_WARNING))
    }
}
