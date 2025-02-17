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

package ee.openeid.siva.test.validate.asice

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.getCERT_VALIDATION_NOT_CONCLUSIVE
import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath
import static org.hamcrest.Matchers.*

class AsiceValidationReportValueVerificationSpec extends GenericSpecification {

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT_TM, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtTmSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TwoValidTmSignaturesWithRolesAndProductionPlace.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("id-2d1a98a8173d01473aa7e88bc74b361a"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.givenName", is("MARI-LIIS"))
                .body("signatures[0].subjectDistinguishedName.surname", is("MÄNNIK"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("test.txt"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2020-05-29T08:19:25Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIMebaUX4S1RLE7lcDJ0LxdLQQBgFsGxID+wzbAPvz8Ti"))
                .body("signatures[0].info.bestSignatureTime", is("2020-05-29T08:19:27Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Signing as king of signers"))
                .body("signatures[0].info.signerRole[1].claimedRole", is("Second role"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Elbonia"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("Harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is("32323"))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2020-05-29T08:19:27Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIGHjCCBAagAwIBAgIQNcO4eO0xcsNbIk36aVrDqjANBgkqhk"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("TwoValidTmSignaturesWithRolesAndProductionPlace.bdoc"))
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validTsSignatureWithRolesAndProductionPlace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("id-7022c18f415891f9cb9124927ab14cfb"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("PNOEE-38001085718"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].subjectDistinguishedName.givenName", is("JAAK-KRISTJAN"))
                .body("signatures[0].subjectDistinguishedName.surname", is("JÕEORG"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("test.txt"))
                .body("signatures[0].signatureScopes[0].scope", is("FULL"))
                .body("signatures[0].signatureScopes[0].content", is("Full document"))
                .body("signatures[0].claimedSigningTime", is("2020-05-29T09:34:56Z"))
                .body("signatures[0].warnings.content", emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIB00XgQZ74rCQz13RlPDKtFVtGiUX01R5rTbhkZZKv0M"))
                .body("signatures[0].info.bestSignatureTime", is("2020-05-29T09:34:58Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("First role"))
                .body("signatures[0].info.signerRole[1].claimedRole", is("Second role"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Some country"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("ÕÄLnül23#&()"))
                .body("signatures[0].info.signatureProductionPlace.city", is("City with spaces"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is("123456789"))
                .body("signatures[0].info.ocspResponseCreationTime", is("2020-05-29T09:35:00Z"))
                .body("signatures[0].info.timestampCreationTime", is("2020-05-29T09:34:58Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID6jCCA02gAwIBAgIQR+qcVFxYF1pcSy/QGEnMVjAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("TEST of ESTEID2018"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIFfDCCBN2gAwIBAgIQNhjzSfd2UEpbkO14EY4ORTAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("DEMO of SK TSA 2014"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhk"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("validTsSignatureWithRolesAndProductionPlace.asice"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtSignatureAdesWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subIndication", emptyOrNullString())
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("build.xml"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2014-07-11T14:10:07Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEINHGGgGzXqzGfN2J6olA6VaXSeCG1PRBGrmG4wxQYf7A"))
                .body("signatures[0].info.bestSignatureTime", is("2011-10-15T14:59:35Z"))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2011-10-15T14:59:35Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT-TM, AdESqc")
    def "bdocCorrectValuesArePresentInvalidLtSignatureAdesqc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("testAdesQCInvalid.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S1510667783001"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.NOT_ADES_QC))
                .body("signatures[0].signedBy", is("NURM,AARE,38211015222"))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("HASH_FAILURE"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signatureScopes[0].name", is("test.pdf"))
                .body("signatures[0].signatureScopes[0].scope", is("FULL"))
                .body("signatures[0].signatureScopes[0].content", is("Full document"))
                .body("signatures[0].claimedSigningTime", is("2017-11-14T13:56:23Z"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[0].info.timeAssertionMessageImprint", emptyOrNullString())
                .body("signatures[0].info.bestSignatureTime", is("2017-11-14T13:56:34Z"))
                .body("signatures[0].info.ocspResponseCreationTime", is("2017-11-14T13:56:35Z"))
                .body("signatures[0].info.timestampCreationTime", is("2017-11-14T13:56:34Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("NURM,AARE,PNOEE-38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIHkDCCBXigAwIBAgIQE2MaQOlx//NYkuLVlIRaIzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("EID-SK 2016"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIG4jCCBcqgAwIBAgIQO4A6a2nBKoxXxVAFMRvE2jANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("testAdesQCInvalid.asice"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("JSON structure has all elements (Bdoc valid multiple signatures)")
    def "bdocAllElementsArePresentValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Baltic MoU digital signing_EST_LT_LV.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("MICHAL,KRISTEN,37507120348"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", is("Baltic MoU digital signing_04112015.docx"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", is("2015-11-04T10:24:11Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEINiaR8aBDIPiXK/fiPb7fe3pWaBaEKzILvjnZVppopPy"))
                .body("signatures[0].info.bestSignatureTime", is("2015-11-04T10:24:20Z"))
                .body("signatures[0].info.timestampCreationTime", emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", is("2015-11-04T10:24:20Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MICHAL,KRISTEN,37507120348"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEoTCCA4mgAwIBAgIQXESH+ckjJK1SC2r9DcQrDzANBgkqhk"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("Baltic MoU digital signing_EST_LT_LV.bdoc"))
                .body("validSignaturesCount", is(3))
                .body("signaturesCount", is(3))
    }

    @Ignore
    //TODO: needs investigation why the signature is determined as XAdES_BASELINE_T not as XAdES_BASELINE_LT_TM
    @Description("JSON structure has all elements (Bdoc indeterminate status)")
    def "bdocAllElementsArePresentIndeterminateSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SS-4_teadmataCA.4.asice", SignaturePolicy.POLICY_3, ReportType.SIMPLE))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", is("S0"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is("signer1"))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", is("The certificate path is not trusted!"))
                .body("signatures[0].errors[1].content", is("The result of the LTV validation process is not acceptable to continue the process!"))
                .body("signatures[0].signatureScopes[0].name", is("test1.txt"))
                .body("signatures[0].signatureScopes[0].scope", is("FULL"))
                .body("signatures[0].signatureScopes[0].content", is("Full document"))
                .body("signatures[0].claimedSigningTime", is("2013-10-11T08:15:47Z"))
                .body("signatures[0].info.timeAssertionMessageImprint", emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", is("libdigidocpp Inter"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIICCTCCAXKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADAnMQswCQ"))
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("SS-4_teadmataCA.4.asice"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("Bdoc report with no signatures")
    def "bdocNoSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerNoSignature.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures", emptyOrNullString())
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", is("BdocContainerNoSignature.bdoc"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
    }

    @Description("Bdoc with LT_TM, LT & LTA signature - timeAssertionMessageImprints in mixed container are reported correctly")
    def "bdocMixedSignaturesContainerCorrectTimeAssertionMessageImprint"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIGzgagluBCVuUgrnT6C5BmSAXBxuuxvlAN7epdGqHP0/"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIBcwYgTTCv5dabbTMJENwex0W1UHxP2OnhiwIcDE89RE"))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIOcfB5FibacEVizcnKhNisrfXU1QyXFzrVGjCQQdntiB"))
    }

    @Description("Asice with LT_TM, LT & LTA signature - timeAssertionMessageImprints in mixed container are reported correctly")
    def "asiceMixedSignaturesContainerCorrectTimeAssertionMessageImprint"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIGzgagluBCVuUgrnT6C5BmSAXBxuuxvlAN7epdGqHP0/"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIBcwYgTTCv5dabbTMJENwex0W1UHxP2OnhiwIcDE89RE"))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.timeAssertionMessageImprint", is("MDEwDQYJYIZIAWUDBAIBBQAEIOcfB5FibacEVizcnKhNisrfXU1QyXFzrVGjCQQdntiB"))

    }

    @Ignore("SIVA-365")
    @Description("Bdoc with B & LT_TM mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "asiceMixedSignaturesSameCertificateContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.ocspResponseCreationTime", is("2021-01-29T14:15:43Z"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", is("2021-01-29T14:31:37Z"))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.ocspResponseCreationTime", is("2021-01-29T14:38:11Z"))
    }

    @Description("Bdoc with LT_TM, LT & LTA signature, LT & LTA with same certificate - ocspResponseCreationTimes in mixed container are reported correctly")
    def "bdocMixedSignaturesSameCertificateContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.ocspResponseCreationTime", is("2021-01-29T14:15:43Z"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", is("2021-01-29T14:31:37Z"))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.ocspResponseCreationTime", is("2021-01-29T14:38:11Z"))
    }

    @Description("Asice with LT & T mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "asiceMixedSignaturesContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2_signatures_T_LT.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", is("2022-08-25T09:05:10Z"))
    }

    @Description("Bdoc with LT-TM & B mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "bdocMixedSignaturesContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2_signatures_B_TM.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B_EPES))
                .body("signatures[0].info", not(hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].info.ocspResponseCreationTime", is("2022-08-25T12:22:37Z"))
    }

    @Description("Filtering out warning \"The trusted certificate does not match the trust service!\" in Simple Report")
    def "bdocFilterTrustServiceWarningSimpleReport"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validTsSignatureWithRolesAndProductionPlace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", not(hasItem(DssMessage.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.message)))
                .body("signatures[0].warnings.content", emptyOrNullString())
    }

    @Description("Filtering out warning \"The certificate is not related to a granted status at time-stamp lowest POE time!\" in Simple Report")
    def "bdocFilterLowestPoeTimeErrorSimpleReport"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4183_3.4kaart_RSA2047_TS.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors.content", not(hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message)))
                .body("signatures[0].errors.content", emptyOrNullString())
    }
}
