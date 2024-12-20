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
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface")
class DdocValidationReportValueVerificationSpec extends GenericSpecification {

    @Description("JSON structure has all elements (ddoc valid single signature)")
    def "ddocAllElementsArePresentValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("DIGIDOC-XML1.3.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signatureLevel", emptyOrNullString())
                .body("signatures[0].signedBy", is("LUKIN,LIISA,47710110274"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("LUKIN,LIISA,47710110274"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47710110274"))
                .body("signatures[0].subjectDistinguishedName.givenName", is("LIISA"))
                .body("signatures[0].subjectDistinguishedName.surname", is("LUKIN"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Glitter-rock-4_gallery.jpg"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("gUCY28PU17SPGDVisO/fc6BEO8E="))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2012-10-03T07:46:51Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("LUKIN,LIISA,47710110274"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEOjCCAyKgAwIBAgIQemG0FEa+2axOwPpfWTLyszANBgkqhk"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("validatedDocument.filename", is("DIGIDOC-XML1.3.ddoc"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("JSON structure has all elements (ddoc invalid signature)")
    def "ddocAllElementsArePresentInvalidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("multipleInvalidSignatures.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signatureLevel", emptyOrNullString())
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", emptyOrNullString())
                .body("signatures[0].errors", hasSize(2))
                .body("signatures[0].signatureScopes[0].name", is("DigiDocService_spec_1_110_est.pdf"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2009-06-01T10:42:19Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("hOU1VZPsg2F65+E9z1gQ0PZ0Gvo="))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2009-06-01T10:42:25Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("validatedDocument.filename", is("multipleInvalidSignatures.ddoc"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(3))
    }

    @Description("Check for optional warning element")
    def "ddocOptionalWarningElementIsPresent"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("18912.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
                .body("validationWarnings[1].content", is("The algorithm SHA1 used in DDOC is no longer considered reliable for signature creation!"))
    }

    @Description("Ddoc report with no signatures")
    def "ddocNoSignature"() {
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

    @Description("Verification of values in Validation Report, xml v1.0, checks for missing info")
    def "ddocCorrectValuesArePresentV1_0"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SK-XML1.0.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is("SK_XML_1.0"))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signedBy", is("ANSIP,ANDRUS,35610012722"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Tartu ja Tallinna koostooleping.doc"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2002-10-07T12:10:19Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: SK-XML version: 1.0"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("+zJk5eEWr1O5QozRwTBxOHtXGWE="))
                .body("signatures[0].info.bestSignatureTime", is("2002-10-07T11:10:47Z"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", emptyOrNullString())
                .body("signatures[0].info.signatureProductionPlace.city", is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", emptyOrNullString())
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2002-10-07T11:10:47Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDuDCCAqCgAwIBAgIEPJilyDANBgkqhkiG9w0BAQUFADB8MR"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ANSIP,ANDRUS,35610012722"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID9zCCAt+gAwIBAgIEPZwyDDANBgkqhkiG9w0BAQUFADB8MR"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_0))
                .body("validatedDocument.filename", is("SK-XML1.0.ddoc"))
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))
    }

    @Description("Verification of values in Validation Report, xml v1.1, checks for missing info")
    def "ddocCorrectValuesArePresentV1_1"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("igasugust1.1.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_1))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[1].name", is("Testilood20070320.doc"))
                .body("signatures[0].signatureScopes[1].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[1].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2009-06-01T10:42:19Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.1"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("hOU1VZPsg2F65+E9z1gQ0PZ0Gvo="))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2009-06-01T10:42:25Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_1))
                .body("validatedDocument.filename", is("igasugust1.1.ddoc"))
                .body("validSignaturesCount", is(3))
                .body("signaturesCount", is(3))
    }

    @Description("Verification of values in Validation Report, xml v1.2, checks for missing info")
    def "ddocCorrectValuesArePresentV1_2"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("igasugust1.2.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_2))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[1].name", is("Testilood20070320.doc"))
                .body("signatures[0].signatureScopes[1].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[1].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2009-06-01T10:45:44Z"))
                .body("signatures[0].warnings[0].content", is("Old and unsupported format: DIGIDOC-XML version: 1.2"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("dnu5mnLqdxKw7QCRT96oshnmMSA="))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("otepää"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2009-06-01T10:45:49Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_2))
                .body("validatedDocument.filename", is("igasugust1.2.ddoc"))
                .body("validSignaturesCount", is(3))
                .body("signaturesCount", is(3))
    }

    @Description("Verification of values in Validation Report, xml v1.3, checks for missing info")
    def "ddocCorrectValuesArePresentV1_3"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("igasugust1.3.ddoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchemaDdoc.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[1].name", is("Testilood20070320.doc"))
                .body("signatures[0].signatureScopes[1].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[1].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2009-06-01T10:46:37Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", is("k5Q9iUHY8M0EJFjaH9h1eWyRgL8="))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("ei tea"))
                .body("signatures[0].info.signatureProductionPlace.city", is("tõrva"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2009-06-01T10:46:42Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", is(ContainerFormat.DIGIDOC_XML_1_3))
                .body("validatedDocument.filename", is("igasugust1.3.ddoc"))
                .body("validSignaturesCount", is(3))
                .body("signaturesCount", is(3))
    }
}
