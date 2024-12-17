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

package ee.openeid.siva.test.validate.ddoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class DdocValidationFailSpec extends GenericSpecification {

    @Description("Ddoc with single invalid signature")
    def "ddocInvalidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AndmefailiAtribuudidMuudetud.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc with multiple invalid signatures")
    def "ddocInvalidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("multipleInvalidSignatures.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors[0].content", is("Bad digest for DataFile: D2"))
                .body("signatures[0].errors[1].content", is("Invalid signature value!"))
                .body("signatures[0].errors.size()", is(2))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[1].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[2].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[2].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(3))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc with multiple signatures both valid and invalid")
    def "ddocInvalidAndValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("multipleValidAndInvalidSignatures.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors[0].content", is("Bad digest for DataFile: D11"))
                .body("signatures[0].errors[1].content", is("Invalid signature value!"))
                .body("signatures[0].errors.size()", is(2))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[1].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[1].warnings.size()", is(1))
                .body("signatures[2].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[2].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(3))
                .body("validSignaturesCount", is(2))
    }

    @Description("Ddoc signature value has been changed (SignatureValue does not correspond to the SignedInfo block)")
    def "ddocSignatureValueChanged"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("test-inv-sig-inf.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors[0].content", containsString("Invalid signature value!"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].info.bestSignatureTime", is("2012-09-19T06:28:55Z"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", notNullValue())
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc Data file(s) don't match the hash values in Reference elements")
    def "ddocDataFileHashMismatch"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AndmefailiAtribuudidMuudetud.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors[0].content", containsString("Bad digest for DataFile: D0"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc Baseline-BES file, no OCSP response")
    def "ddocNoOCSPResponse"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ilma_kehtivuskinnituseta.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_2))
                .body("signatures[0].errors.content", hasItems("Signature has no OCSP confirmation!"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.2"))
                .body("signatures[0].warnings.size()", is(1))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc no non-repudiation key usage value in the certificate")
    def "ddocNoNonRepudiationKey"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("test-non-repu1.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors.content", hasItems("Signers cert does not have non-repudiation bit set!"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].warnings.content", hasItems("X509IssuerName has none or invalid namespace: null", "X509SerialNumber has none or invalid namespace: null"))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc Signer's certificate is not trusted")
    def "ddocSignersCertNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Belgia_kandeavaldus_LIV.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[1].errors.content", hasItems("Signers cert not trusted, missing CA cert!", "Signing certificate issuer information does not match"))
                .body("signatures[1].errors.size()", is(3))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[1].signedBy", is("Ramlot,Guy Marc,65030202936"))
                .body("signatures[1].subjectDistinguishedName.commonName", is("Guy Ramlot (Signature)"))
                .body("signatures[1].subjectDistinguishedName.serialNumber", is("65030202936"))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("Guy Ramlot (Signature)"))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID5DCCAsygAwIBAgIQEAAAAAAA6b6vobxT/DKUOzANBgkqhk"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }

    @Description("Ddoc OCSP certificate is not trusted")
    def "ddocOCSPNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Tundmatu_OCSP_responder.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors.content", hasItems("Signers cert not trusted, missing CA cert!", "Signing certificate issuer information does not match"))
                .body("signatures[0].errors.size()", is(3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("Belgium OCSP Responder"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDTTCCAjWgAwIBAgILBAAAAAABGTkSVnEwDQYJKoZIhvcNAQ"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc has unsigned data files in the container")
    def "ddocNonSignedFile"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.3_lisatud_andmefail.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors.content", hasItems("Missing Reference for file: testfail2.txt"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc signed data file has been removed from the container")
    def "ddocFileRemoved"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("faileemald1.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors.content", hasItems("Missing DataFile for signature: S0 reference #D0"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc wrong nonce")
    def "ddocWrongOcspNonce"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("OCSP nonce vale.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].errors.content", hasItems("Notarys digest doesn't match!", "OCSP response's nonce doesn't match the requests nonce!"))
                .body("signatures[0].errors.size()", is(2))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("validSignaturesCount", is(0))
    }

    @Description("Ddoc with XML Entity expansion attack")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/")
    def "ddocWithXMLEntityExpansionAttackShouldFail"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("xml_expansion.ddoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Ddoc with XML server side request forgery attack")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/")
    def "ddocWithXMLServerSideRequestForgeryAttackShouldFail"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("xml_entity.ddoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Ddoc no files in container")
    def "ddocNoFilesInContainer"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("KS-02_tyhi.ddoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_INVALID_BASE_64, RequestError.DOCUMENT_BLANK)
    }

    @Description("Ddoc with invalid datafile id")
    def "ddocBadDatafileId"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("22915-bad-df-id.ddoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItems("Id attribute value has to be in form D<number> or DO"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].warnings.content", hasItems("X509IssuerName has none or invalid namespace: null", "X509SerialNumber has none or invalid namespace: null"))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].signatureScopes[0].name", is("build.xml"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2013-05-09T18:15:42Z"))
                .body("validatedDocument.filename", is("22915-bad-df-id.ddoc"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
    }

    @Description("Validation of DDOC with revoked certificate status")
    def "ddocWithRevokedCertificateStatusFromOcspShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("cert-revoked.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItems("Certificate has been revoked!"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].warnings.content", hasItems("X509IssuerName has none or invalid namespace: null", "X509SerialNumber has none or invalid namespace: null"))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].signatureScopes[0].name", is("build.xml"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2013-05-17T12:15:08Z"))
                .body("validatedDocument.filename", is("cert-revoked.ddoc"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
    }

    @Description("Validation of DDOC with unknown OCSP status")
    def "ddocWithUnknownCertificateStatusFromOcspShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("cert-unknown.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItems("Certificate status is unknown!"))
                .body("signatures[0].errors.size()", is(1))
                .body("signatures[0].warnings.content", hasItems("X509IssuerName has none or invalid namespace: null", "X509SerialNumber has none or invalid namespace: null"))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].signatureScopes[0].name", is("build.xml"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2013-05-17T12:20:18Z"))
                .body("validatedDocument.filename", is("cert-unknown.ddoc"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
                .body("validationWarnings", hasSize(2))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
    }
}
