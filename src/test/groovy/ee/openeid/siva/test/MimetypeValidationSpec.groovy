/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test

import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.apache.http.HttpStatus
import org.hamcrest.Matchers

import static ee.openeid.siva.common.Constants.*
import static ee.openeid.siva.integrationtest.TestData.*

@Link("http://open-eid.github.io/SiVa/siva3/overview/#main-features-of-siva-validation-service")
class MimetypeValidationSpec extends GenericSpecification {

    @Description("ASICe container with valid mimetype.")
    def "asiceValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerValidMimetype.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid ASICe container with mimetype as last in cointainer.")
    def "asiceInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeAsLast.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container with deflated mimetype.")
    def "asiceInvalidMimetypeCompressionAsDeflated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeIsDeflated.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid ASICe container without mimetype.")
    def "asiceWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerNoMimetype.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container mimetype filename with capital letter (Mimetype).")
    def "asiceMimetypeFileNameWithCapitalLetter"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeWithCapitalLetter.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "asiceMimetypeFilenameWithExtraSpace"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeFilenameWithExtraSpace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICe container with extra byte in the beginning of the container.")
    def "asiceContainerWithExtraByteInBeginning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerMimetypeWithCapitalLetter.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("ASICe container with invalid mimetype as \"text/plain\".")
    def "asiceInvalidMimetypeAsText"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceInvalidMimetypeAsText.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_INVALID_TYPE))
    }

    @Description("BDOC container with valid mimetype.")
    def "bdocValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerValidMimetype.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid BDOC container with mimetype as last.")
    def "bdocInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerMimetypeAsLast.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid BDOC container with deflated mimetype.")
    def "bdocInvalidMimetypeCompressionAsDeflated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerMimetypeIsDeflated.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid BDOC container without mimetype.")
    def "bdocWithNoMimetype"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("BdocContainerNoMimetype.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .rootPath("requestErrors[0]")
                .body("message", Matchers.is("Document malformed or not matching documentType"))
    }

    @Description("Invalid BDOC container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "bdocMimetypeFilenameWithExtraSpace"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("BdocContainerMimetypeFilenameWithExtraSpace.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .rootPath("requestErrors[0]")
                .body("message", Matchers.is("Document malformed or not matching documentType"))
    }

    @Description("BDOC container with invalid mimetype as \"application/zip\".")
    def "bdocInvalidMimetypeAsZip"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("BdocInvalidMimetypeAsZip.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .rootPath("requestErrors[0]")
                .body("message", Matchers.is("Document malformed or not matching documentType"))
    }

    @Description("ASICs container with valid mimetype and Tmp file inside.")
    def "asicsValidMimetypeWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerValidMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
    }

    @Description("ASICs container with valid mimetype and DDOC inside.")
    def "asicsValidMimetypeWithDdocContainer"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerValidMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is("DIGIDOC_XML_1.3"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid ASICs container with mimetype as last and Tmp file inside.")
    def "asicsInvalidMimetypeLocationAsLastWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeAsLast.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container with mimetype as last and DDOC inside.")
    def "asicsInvalidMimetypeLocationAsLastWithDdoc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerMimetypeAsLast.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is("DIGIDOC_XML_1.3"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container with deflated mimetype and Tmp file inside.")
    def "asicsInvalidMimetypeCompressionAsDeflatedWithTmpFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeIsDeflated.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid ASICs container with deflated mimetype and DDOC inside.")
    def "asicsInvalidMimetypeCompressionAsDeflatedWithDdoc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerMimetypeIsDeflated.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is("DIGIDOC_XML_1.3"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_COMPRESSED_WARNING))
    }

    @Description("Invalid ASICs container without mimetype and Tmp file inside.")
    def "asicsContainingTmpFileWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerNoMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container without mimetype and DDOC inside.")
    def "asicsContainingDdocContainerWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Ddoc_as_AsicsContainerNoMimetype.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is("DIGIDOC_XML_1.3"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid ASICs container, where mimetype filename is with extra space in the end (\"mimetype \").")
    def "asicsMimetypeFilenameWithExtraSpace"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsContainerMimetypeFilenameWithExtraSpace.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
                .body("signatures[0].errors.content", Matchers.hasItem("The manifest file is absent!"))
    }

    @Description("ASICs container with invalid mimetype as \"application/xml\".")
    def "asicsInvalidMimetypeAsXml"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsicsInvalidMimetypeAsXml.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_INVALID_TYPE))
    }

    @Description("Valid EDOC container with valid.")
    def "edocValidMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerValidMimetype.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Invalid EDOC container with mimetype as last in cointainer.")
    def "edocInvalidMimetypeLocationAsLast"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerValidMimetypeAsLast.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Invalid EDOC container without mimetype.")
    def "edocWithNoMimetype"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EdocContainerNoMimetype.edoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_NOT_FIRST_WARNING))
    }

    @Description("Valid ADOC container with mimetype.")
    def "adocMimetypeWithExtraFields"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AdocContainerMimetypeWithExtraFields.adoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-S"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("validationWarnings", Matchers.hasSize(2))
                .body("validationWarnings.content", Matchers.hasItem(MIMETYPE_EXTRA_FIELDS_WARNING))
    }
}