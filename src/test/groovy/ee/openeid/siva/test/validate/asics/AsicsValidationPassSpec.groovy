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

package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import org.hamcrest.Matchers
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX

class AsicsValidationPassSpec extends GenericSpecification {

    @Description("Validation of ASICs with DDOC inside")
    def "validDdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ddocWithRoleAndSigProductionPlace.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2009-06-01T10:46:42Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", Matchers.is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", Matchers.is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", Matchers.is("ei tea"))
                .body("signatures[0].info.signatureProductionPlace.city", Matchers.is("tõrva"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", Matchers.is(" "))
                .body("signatures[0].signedBy", Matchers.is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2020-06-02T11:18:22Z"))
                .body("timeStampTokens[0].certificates[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].certificates[0].type", Matchers.is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content", Matchers.startsWith("MIIEFjCCAv6gAwIBAgIQYjZ9dFrZQ6tdpFC5Xj/6bjANBgkqhk"))
                .body("validatedDocument.filename", Matchers.is("ddocWithRoleAndSigProductionPlace.asics"))
                .body("signaturesCount", Matchers.is(3))
                .body("validSignaturesCount", Matchers.is(3))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with DDOC inside SCS extension")
    def "validDdocInsideValidAsicsScsExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.scs"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", Matchers.is("ValidDDOCinsideAsics.scs"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", Matchers.is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2012-10-03T07:46:51Z"))
                .body("signatures[0].signedBy", Matchers.is("LUKIN,LIISA,47710110274"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with BDOC inside")
    def "validBdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidBDOCinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", Matchers.is("ValidBDOCinsideAsics.asics"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-05-11T10:18:06Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", Matchers.is("Signer / Proper signature"))
                .body("signatures[0].info.signatureProductionPlace.countryName", Matchers.is("Estonia"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", Matchers.is("Harju"))
                .body("signatures[0].info.signatureProductionPlace.city", Matchers.is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", Matchers.is("22333"))
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("38211015222"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].info.bestSignatureTime", Matchers.is("2016-05-11T10:19:38Z"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", Matchers.is(2))
                .body("validSignaturesCount", Matchers.is(2))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with text document inside")
    def "textInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TXTinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-25T09:56:33Z"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(0))
                .body("validatedDocument.filename", Matchers.is("TXTinsideAsics.asics"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with ASICs inside")
    def "asicsInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidASICSinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-25T11:24:01Z"))
                .body("validatedDocument.filename", Matchers.is("ValidASICSinsideAsics.asics"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with DDOC inside ZIP extension")
    def "ValidDdocInsideValidAsicsZipExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.zip"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", Matchers.is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
                .body("validatedDocument.filename", Matchers.is("ValidDDOCinsideAsics.zip"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with wrong mimetype with DDOC inside")
    def "ValidDdocInsideValidAsicsWrongMimeType"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsicsWrongMime.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", Matchers.is("ValidDDOCinsideAsicsWrongMime.asics"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", Matchers.is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", Matchers.is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
    }
}
