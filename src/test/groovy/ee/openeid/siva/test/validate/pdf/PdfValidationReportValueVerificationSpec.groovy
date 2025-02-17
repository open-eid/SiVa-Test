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

package ee.openeid.siva.test.validate.pdf

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.*
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface")
class PdfValidationReportValueVerificationSpec extends GenericSpecification {

    @Description("JSON structure has all elements (Pdf valid single signature). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("reason_and_location_Test.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S-4D0D5A83688FC617AA83810ED74E26C5A79063D110B00AD207EAB3EFDC3F5619"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("11404176865"))
                .body("signatures[0].subjectDistinguishedName.givenName", is("MÄRÜ-LÖÖZ"))
                .body("signatures[0].subjectDistinguishedName.surname", is("ŽÕRINÜWŠKY"))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Partial PDF"))
                .body("signatures[0].signatureScopes[0].scope", is("PARTIAL"))
                .body("signatures[0].signatureScopes[0].content", is("The document ByteRange : [0, 2226, 21172, 314]"))
                .body("signatures[0].claimedSigningTime", is("2020-05-27T09:59:07Z"))
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIDqs93c5A/EZVW0YfLVkSS3NeO716K6Kb0Mcr/ewLCmA"))
                .body("signatures[0].info.bestSignatureTime", is("2020-05-27T09:59:09Z"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Narva"))
                .body("signatures[0].info.signingReason", is("Roll??"))
                .body("signatures[0].info.ocspResponseCreationTime", is("2020-05-27T09:59:10Z"))
                .body("signatures[0].info.timestampCreationTime", is("2020-05-27T09:59:09Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIFrjCCA5agAwIBAgIQUwvkG7xZfERXDit8E7z6DDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("TEST of ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIGgzCCBWugAwIBAgIQEDb9gCZi4PdWc7IoNVIbsTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("DEMO of SK TSA 2014"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhk"))
                .body("signatureForm", emptyOrNullString())
                .body("validatedDocument.filename", is("reason_and_location_Test.pdf"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("JSON structure has all elements (Pdf valid Multiple signatures). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades_lt_two_valid_sig.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[1].id", is("S-E5D6D118C4B604343E1395213075D5C429CD68E9178E4E8252EDB027732EF3F6"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[1].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                .body("signatures[1].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[1].signedBy", is("VOLL,ANDRES,39004170346"))
                .body("signatures[1].subjectDistinguishedName.commonName", is("VOLL,ANDRES,39004170346"))
                .body("signatures[1].subjectDistinguishedName.serialNumber", is("39004170346"))
                .body("signatures[1].indication", is("TOTAL-PASSED"))
                .body("signatures[1].errors", emptyOrNullString())
                .body("signatures[1].signatureScopes[0].name", is("Partial PDF"))
                .body("signatures[1].signatureScopes[0].scope", is("PARTIAL"))
                .body("signatures[1].signatureScopes[0].content", is("The document ByteRange : [0, 134940, 153886, 24208]"))
                .body("signatures[1].claimedSigningTime", is("2016-06-27T09:59:37Z"))
                .body("signatures[1].warnings", emptyOrNullString())
                .body("signatures[1].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIOjVGatd9zXaIv/XQ9c81bTjZ4K14Ihcrhwv+sBhM26V"))
                .body("signatures[1].info.bestSignatureTime", is("2016-06-27T09:59:48Z"))
                .body("signatures[1].info.ocspResponseCreationTime", is("2016-06-27T09:59:49Z"))
                .body("signatures[1].info.timestampCreationTime", is("2016-06-27T09:59:48Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEmDCCA4CgAwIBAgIQP0r+1SmYLpVSgfYqBWYcBzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", emptyOrNullString())
                .body("validatedDocument.filename", is("pades_lt_two_valid_sig.pdf"))
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))
    }

    @Description("JSON structure has all elements (Pdf invalid signature). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentInvalidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-b.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[1].id", is("S-9D2DD421E47AE2C851EBD4C467DA97042362BB48331511E272B64110CFF862EE"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[1].signatureLevel", is(SignatureLevel.NOT_ADES))
                .body("signatures[1].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].subIndication", is("FORMAT_FAILURE"))
                .body("signatures[1].errors.content", hasItem(CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("signatures[1].signatureScopes[0].name", is("Full PDF"))
                .body("signatures[1].signatureScopes[0].scope", is("FULL"))
                .body("signatures[1].signatureScopes[0].content", is("The document ByteRange : [0, 94483, 132377, 492]"))
                .body("signatures[1].claimedSigningTime", is("2015-08-23T05:10:15Z"))
                .body("signatures[1].warnings[0].content", is("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].info.timeAssertionMessageImprint", emptyOrNullString())
                .body("signatures[1].info.bestSignatureTime", emptyOrNullString())
                .body("signatures[1].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[1].info.ocspResponseCreationTime", is("2015-08-23T05:08:41Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEnTCCA4WgAwIBAgIQURtcmP07BjlUmR1RPIeGCTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", emptyOrNullString())
                .body("validatedDocument.filename", is("hellopades-lt-b.pdf"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }

    @Description("JSON structure has all elements (Pdf indeterminate status). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentIndeterminateSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-rsa1024-sha1-expired.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S-B2DE2D1E57C3DD8F518A13F027988A4BDBE03DC7A1DF96301351694DCDB88213"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItem(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signatureScopes[0].name", is("Partial PDF"))
                .body("signatures[0].signatureScopes[0].scope", is("PARTIAL"))
                .body("signatures[0].signatureScopes[0].content", is("The document ByteRange : [0, 14153, 52047, 491]"))
                .body("signatures[0].claimedSigningTime", is("2012-01-24T11:08:15Z"))
                .body("signatures[0].warnings", hasSize(5))
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIFx5F/YSDew7evstDVhsdXKaN1B3k/wDBgLOOs1YFdJr"))
                .body("signatures[0].info.bestSignatureTime", is("2015-08-24T10:08:25Z"))
                .body("signatures[0].info.timestampCreationTime", is("2015-08-24T10:08:25Z"))
                .body("signatures[0].info.ocspResponseCreationTime", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("ESTEID-SK 2007"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIID0zCCArugAwIBAgIERZugDTANBgkqhkiG9w0BAQUFADBdMR"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", emptyOrNullString())
                .body("validatedDocument.filename", is("hellopades-lt-rsa1024-sha1-expired.pdf"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("Pdf report with no signatures. Report is returned with required elements")
    def "pdfNoSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PdfNoSignature.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures", emptyOrNullString())
                .body("signatureForm", emptyOrNullString())
                .body("validatedDocument.filename", is("PdfNoSignature.pdf"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
    }

    @Ignore("SIVA-365")
    @Description("PDF with PAdES-LT and B signatures with same signer certificate - ocspResponseCreationTimes in mixed container are reported correctly. ocspResponseCreationTime for LT is present and for B profile is not.")
    def "pdfMixedSameCertificateSignaturesCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-b.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].info", hasKey("ocspResponseCreationTime"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[1].signatureLevel", is(SignatureLevel.NOT_ADES))
                .body("signatures[1].indication", is("TOTAL-FAILED"))
                .body("signatures[1].info", not(hasKey("ocspResponseCreationTime")))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }

    @Description("PDF with PAdES-T and B profile signatures with different signer certificates - ocspResponseCreationTimes in mixed container are reported correctly. ocspResponseCreationTime for T profile is present and for B profile is not")
    def "pdfMixedDifferentCertificateSignaturesCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-b-lt-sha256-auth.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[0].signatureLevel", is(SignatureLevel.NOT_ADES))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[1].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[1].indication", is("TOTAL-PASSED"))
                .body("signatures[1].info.ocspResponseCreationTime", is("2022-08-23T14:59:17Z"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }
}
