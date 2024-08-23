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

package ee.openeid.siva.test.validate.pdf

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.hamcrest.Matchers
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.*
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface")
class PdfValidationReportValueVerificationSpec extends GenericSpecification {

    @Description("JSON structure has all elements (Pdf valid single signature). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("reason_and_location_Test.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S-4D0D5A83688FC617AA83810ED74E26C5A79063D110B00AD207EAB3EFDC3F5619"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("11404176865"))
                .body("signatures[0].subjectDistinguishedName.givenName", Matchers.is("MÄRÜ-LÖÖZ"))
                .body("signatures[0].subjectDistinguishedName.surname", Matchers.is("ŽÕRINÜWŠKY"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].errors", Matchers.emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", Matchers.is("Partial PDF"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("PARTIAL"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("The document ByteRange : [0, 2226, 21172, 314]"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2020-05-27T09:59:07Z"))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIDqs93c5A/EZVW0YfLVkSS3NeO716K6Kb0Mcr/ewLCmA"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2020-05-27T09:59:09Z"))
                .body("signatures[0].info.signatureProductionPlace.countryName", Matchers.is("Narva"))
                .body("signatures[0].info.signingReason", Matchers.is("Roll??"))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2020-05-27T09:59:10Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.is("2020-05-27T09:59:09Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIFrjCCA5agAwIBAgIQUwvkG7xZfERXDit8E7z6DDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("TEST of ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIGgzCCBWugAwIBAgIQEDb9gCZi4PdWc7IoNVIbsTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("DEMO of SK TSA 2014"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhk"))
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("validatedDocument.filename", Matchers.is("reason_and_location_Test.pdf"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("JSON structure has all elements (Pdf valid Multiple signatures). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades_lt_two_valid_sig.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[1].id", Matchers.is("S-E5D6D118C4B604343E1395213075D5C429CD68E9178E4E8252EDB027732EF3F6"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[1].signatureMethod", Matchers.is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                .body("signatures[1].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[1].signedBy", Matchers.is("VOLL,ANDRES,39004170346"))
                .body("signatures[1].subjectDistinguishedName.commonName", Matchers.is("VOLL,ANDRES,39004170346"))
                .body("signatures[1].subjectDistinguishedName.serialNumber", Matchers.is("39004170346"))
                .body("signatures[1].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[1].errors", Matchers.emptyOrNullString())
                .body("signatures[1].signatureScopes[0].name", Matchers.is("Partial PDF"))
                .body("signatures[1].signatureScopes[0].scope", Matchers.is("PARTIAL"))
                .body("signatures[1].signatureScopes[0].content", Matchers.is("The document ByteRange : [0, 134940, 153886, 24208]"))
                .body("signatures[1].claimedSigningTime", Matchers.is("2016-06-27T09:59:37Z"))
                .body("signatures[1].warnings", Matchers.emptyOrNullString())
                .body("signatures[1].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIOjVGatd9zXaIv/XQ9c81bTjZ4K14Ihcrhwv+sBhM26V"))
                .body("signatures[1].info.bestSignatureTime", Matchers.is("2016-06-27T09:59:48Z"))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2016-06-27T09:59:49Z"))
                .body("signatures[1].info.timestampCreationTime", Matchers.is("2016-06-27T09:59:48Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEmDCCA4CgAwIBAgIQP0r+1SmYLpVSgfYqBWYcBzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("validatedDocument.filename", Matchers.is("pades_lt_two_valid_sig.pdf"))
                .body("validSignaturesCount", Matchers.is(2))
                .body("signaturesCount", Matchers.is(2))
    }

    @Description("JSON structure has all elements (Pdf invalid signature). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentInvalidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-b.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[1].id", Matchers.is("S-9D2DD421E47AE2C851EBD4C467DA97042362BB48331511E272B64110CFF862EE"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[1].signatureLevel", Matchers.is(SignatureLevel.NOT_ADES))
                .body("signatures[1].signedBy", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[1].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[1].subIndication", Matchers.is("FORMAT_FAILURE"))
                .body("signatures[1].errors.content", Matchers.hasItem(CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("signatures[1].signatureScopes[0].name", Matchers.is("Full PDF"))
                .body("signatures[1].signatureScopes[0].scope", Matchers.is("FULL"))
                .body("signatures[1].signatureScopes[0].content", Matchers.is("The document ByteRange : [0, 94483, 132377, 492]"))
                .body("signatures[1].claimedSigningTime", Matchers.is("2015-08-23T05:10:15Z"))
                .body("signatures[1].warnings[0].content", Matchers.is("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[1].info.timeAssertionMessageImprint", Matchers.emptyOrNullString())
                .body("signatures[1].info.bestSignatureTime", Matchers.emptyOrNullString())
                .body("signatures[1].info.timestampCreationTime", Matchers.emptyOrNullString())
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2015-08-23T05:08:41Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEnTCCA4WgAwIBAgIQURtcmP07BjlUmR1RPIeGCTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("validatedDocument.filename", Matchers.is("hellopades-lt-b.pdf"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(2))
    }

    @Description("JSON structure has all elements (Pdf indeterminate status). All required elements are present according to SimpleReportSchema.json")
    def "pdfAllElementsArePresentIndeterminateSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-rsa1024-sha1-expired.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S-B2DE2D1E57C3DD8F518A13F027988A4BDBE03DC7A1DF96301351694DCDB88213"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].signedBy", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItem(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signatureScopes[0].name", Matchers.is("Partial PDF"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("PARTIAL"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("The document ByteRange : [0, 14153, 52047, 491]"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2012-01-24T11:08:15Z"))
                .body("signatures[0].warnings", Matchers.hasSize(5))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIFx5F/YSDew7evstDVhsdXKaN1B3k/wDBgLOOs1YFdJr"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2015-08-24T10:08:25Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.is("2015-08-24T10:08:25Z"))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("ESTEID-SK 2007"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIID0zCCArugAwIBAgIERZugDTANBgkqhkiG9w0BAQUFADBdMR"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("validatedDocument.filename", Matchers.is("hellopades-lt-rsa1024-sha1-expired.pdf"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("Pdf report with no signatures. Report is returned with required elements")
    def "pdfNoSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PdfNoSignature.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures", Matchers.emptyOrNullString())
                .body("signatureForm", Matchers.emptyOrNullString())
                .body("validatedDocument.filename", Matchers.is("PdfNoSignature.pdf"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(0))
    }

    @Ignore("SIVA-365")
    @Description("PDF with PAdES-LT and B signatures with same signer certificate - ocspResponseCreationTimes in mixed container are reported correctly. ocspResponseCreationTime for LT is present and for B profile is not.")
    def "pdfMixedSameCertificateSignaturesCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-b.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].info", Matchers.hasKey("ocspResponseCreationTime"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[1].signatureLevel", Matchers.is(SignatureLevel.NOT_ADES))
                .body("signatures[1].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[1].info", Matchers.not(Matchers.hasKey("ocspResponseCreationTime")))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(2))
    }

    @Description("PDF with PAdES-T and B profile signatures with different signer certificates - ocspResponseCreationTimes in mixed container are reported correctly. ocspResponseCreationTime for T profile is present and for B profile is not")
    def "pdfMixedDifferentCertificateSignaturesCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-pades-b-lt-sha256-auth.pdf"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_B))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.NOT_ADES))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].info", Matchers.not(Matchers.hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[1].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[1].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2022-08-23T14:59:17Z"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(2))
    }
}
