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
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.is

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy")
class DdocValidationPassSpec extends GenericSpecification {

    @Description("Ddoc v1.0 with valid signatures")
    def "ddocValidMultipleSignaturesV1_0"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SK-XML1.0.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_0))
                .body("signatures[0].signatureFormat", is(SignatureFormat.SK_XML))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: SK-XML version: 1.0"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[1].signatureFormat", is(SignatureFormat.SK_XML))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].warnings[0].content", is("Old and unsupported format: SK-XML version: 1.0"))
                .body("signatures[1].warnings.size()", is(1))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    @Description("Ddoc v1.1 with valid signature")
    def "ddocValidSignatureV1_1"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.1.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.2 with valid signature")
    def "ddocValidSignatureV1_2"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.2.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_2))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_2))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.2"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.3 with valid signature with ESTEID-SK 2011 certificate chain")
    def "ddocValidSignatureV1_3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.3.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.3 with valid signature, signed data file name has special characters and ESTEID-SK certificate chain")
    def "ddocSpecialCharactersInDataFileValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("susisevad1_3.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.3 KLASS3-SK certificate chain with valid signature")
    def "ddocKlass3SkCertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("KLASS3-SK _ KLASS3-SK OCSP RESPONDER uus.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("SK: dokumendi kinnitus"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("SK: dokumendi kinnitus"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("10747013"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("KLASS3-SK OCSP RESPONDER"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.3 KLASS3-SK 2010 certificate chain with valid signature")
    def "ddocKlass3Sk2010CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("KLASS3-SK 2010 _ KLASS3-SK 2010 OCSP RESPONDER.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("Sertifitseerimiskeskus AS Klienditoe osakond"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("KLASS3-SK 2010 OCSP RESPONDER"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.1 ESTEID-SK 2007 certificate chain with valid signature")
    def "ddocEsteidSk2007CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("vaikesed1.1.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.1 ESTEID-SK 2015 certificate chain with valid signature")
    def "ddocEsteidSk2015CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4270_ESTEID-SK 2015  SK OCSP RESPONDER 2011.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("LUKIN,LIISA,47710110274"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.1 ESTEID-SK certificate chain with valid signature")
    def "ddocEsteidSkCertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EID-SK _ EID-SK OCSP RESPONDER.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("EID-SK OCSP RESPONDER"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.1 ESTEID-SK 2007 and OCSP 2010 certificate chain with valid signature")
    def "ddocEsteidSk2007Ocsp2010CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EID-SK 2007 _ EID-SK 2007 OCSP RESPONDER 2010.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("EID-SK 2007 OCSP RESPONDER 2010"))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    @Description("Ddoc v1.3 ESTEID-SK 2007 and OCSP 2007 certificate chain with valid signature")
    def "ddocEsteidSk2007Ocsp2007CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EID-SK 2007 _ EID-SK 2007 OCSP RESPONDER.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("EID-SK 2007 OCSP RESPONDER"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc v1.3 ESTEID-SK 2011 and OCSP 2011 certificate chain with valid signature")
    def "ddocEsteidSk2011Ocsp2011CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EID-SK 2011 _ SK OCSP RESPONDER 2011.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings[0].content", is("X509IssuerName has none or invalid namespace: null"))
                .body("signatures[0].warnings[1].content", is("X509SerialNumber has none or invalid namespace: null"))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].signedBy", is("PELANIS,MINDAUGAS,37412260478"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Ddoc with warning should pass")
    def "ddocWithWarningShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("18912.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("36706020210"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("readme"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2012-09-21T11:56:53Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-09-21T11:56:55Z"))
                .body("signatures[0].warnings[0].content", is("Bad digest for DataFile: D0 alternate digest matches!"))
                .body("signatures[0].warnings.size()", is(1))
                .body("validatedDocument.filename", is("18912.ddoc"))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Ddoc with no signatures")
    def "ddocNoSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DdocContainerNoSignature.ddoc", SignaturePolicy.POLICY_4, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("validatedDocument.filename", is("DdocContainerNoSignature.ddoc"))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
    }

    @Description("Validation of DDOC Hashcode v1.0")
    def "ddocV1_0HashcodeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SK-XML1_0_hashcode.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_0_hashcode))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.SK_XML))
                .body("signatures[0].signedBy", is("ANSIP,ANDRUS,35610012722"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Tartu ja Tallinna koostooleping.doc"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2002-10-07T12:10:19Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: SK-XML version: 1.0"))
                .body("signatures[0].warnings.size()", is(1))
                .body("signatures[0].info.bestSignatureTime", is("2002-10-07T11:10:47Z"))
                .body("validatedDocument.filename", is("SK-XML1_0_hashcode.ddoc"))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
    }

    @Description("Validation of DDOC Hashcode v1.1")
    def "ddocV1_1HashcodeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.1_hashcode.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1_hashcode))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signedBy", is("KESKEL,URMO,38002240232"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("puhkus_urmo_062006.doc"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2006-06-26T12:15:40Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].warnings.size()", is(1))
                .body("validatedDocument.filename", is("DIGIDOC-XML1.1_hashcode.ddoc"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Validation of DDOC Hashcode v1.2")
    def "ddocV1_2HashcodeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.2_hashcode.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_2_hashcode))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_2))
                .body("signatures[0].signatureLevel", emptyOrNullString())
                .body("signatures[0].signedBy", is("Eesti Ühispank: Ülekandejuhise kinnitus"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subIndication", emptyOrNullString())
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("RO219559508.pdf"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2003-10-24T10:57:19Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.2"))
                .body("signatures[0].warnings.size()", is(1))
                .body("validatedDocument.filename", is("DIGIDOC-XML1.2_hashcode.ddoc"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Validation of DDOC Hashcode v1.3")
    def "ddocV1_3HashcodeShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.3_hashcode.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3_hashcode))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureLevel", emptyOrNullString())
                .body("signatures[0].signedBy", is("LUKIN,LIISA,47710110274"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subIndication", emptyOrNullString())
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Glitter-rock-4_gallery.jpg"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validatedDocument.filename", is("DIGIDOC-XML1.3_hashcode.ddoc"))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }
}
