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
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.startsWith

class AsicsValidationPassSpec extends GenericSpecification {

    @Description("Validation of ASICs with DDOC inside")
    def "validDdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ddocWithRoleAndSigProductionPlace.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].info.bestSignatureTime", is("2009-06-01T10:46:42Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("ei tea"))
                .body("signatures[0].info.signatureProductionPlace.city", is("tõrva"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].signedTime", is("2020-06-02T11:18:22Z"))
                .body("timeStampTokens[0].certificates[0].commonName", is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].certificates[0].type", is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content", startsWith("MIIEFjCCAv6gAwIBAgIQYjZ9dFrZQ6tdpFC5Xj/6bjANBgkqhk"))
                .body("validatedDocument.filename", is("ddocWithRoleAndSigProductionPlace.asics"))
                .body("signaturesCount", is(3))
                .body("validSignaturesCount", is(3))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with DDOC inside SCS extension")
    def "validDdocInsideValidAsicsScsExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.scs"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsics.scs"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("signatures[0].signedBy", is("LUKIN,LIISA,47710110274"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with BDOC inside")
    def "validBdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidBDOCinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidBDOCinsideAsics.asics"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2016-05-11T10:18:06Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Signer / Proper signature"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Estonia"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("Harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is("22333"))
                .body("signatures[0].signedBy", is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("38211015222"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("NURM,AARE,38211015222"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].info.bestSignatureTime", is("2016-05-11T10:19:38Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with text document inside")
    def "textInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TXTinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-25T09:56:33Z"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
                .body("validatedDocument.filename", is("TXTinsideAsics.asics"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with ASICs inside")
    def "asicsInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidASICSinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-25T11:24:01Z"))
                .body("validatedDocument.filename", is("ValidASICSinsideAsics.asics"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with DDOC inside ZIP extension")
    def "ValidDdocInsideValidAsicsZipExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.zip"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsics.zip"))
    }

    @Ignore("SIVA-748 needs a new container")
    @Description("Validation of ASICs with wrong mimetype with DDOC inside")
    def "ValidDdocInsideValidAsicsWrongMimeType"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsicsWrongMime.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsicsWrongMime.asics"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }
}
