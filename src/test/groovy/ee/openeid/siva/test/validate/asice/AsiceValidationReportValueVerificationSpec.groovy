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

    @Ignore("SIVA-848")
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

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given ASiC-E with timestamped signature, then validation report includes timestampCreationTime field"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[0].info.timestampCreationTime", is(timestampCreationTime))

        where:
        file                                   | timestampCreationTime
        "TEST_ESTEID2018_ASiC-E_XAdES_T.sce"   | "2024-09-13T14:14:24Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"  | "2024-09-13T14:14:36Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce" | "2024-09-13T14:14:47Z"
        "TEST_ESTEID2018_ASiC-E_CAdES_T.sce"   | "2024-09-13T14:15:13Z"
        "TEST_ESTEID2018_ASiC-E_CAdES_LT.sce"  | "2024-09-13T14:15:28Z"
        "TEST_ESTEID2018_ASiC-E_CAdES_LTA.sce" | "2024-09-13T14:15:38Z"
    }

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given ASiC-E with multiple timestamped signatures, then validation report includes timestampCreationTime field for each"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.sce"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[1].info.timestampCreationTime", is("2021-01-29T14:31:36Z"))
                .body("signatures[2].info.timestampCreationTime", is("2021-01-29T14:38:11Z"))
    }

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-E with archive timestamped signature, then validation report includes archiveTimeStamps object"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file)).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.findAll { it.signatureFormat.contains('LTA') }.size()",
                        is(ltaCount))
                .body("signatures.findAll { it.signatureFormat.contains('LTA') }.info",
                        everyItem(hasKey("archiveTimeStamps")))
                .body("signatures.findAll { !it.signatureFormat.contains('LTA') }.info",
                        everyItem(not(hasKey("archiveTimeStamps"))))

        where:
        file                                       | ltaCount
        "TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce"     | 1
        "TEST_ESTEID2018_ASiC-E_XAdES_LT+LTA.sce"  | 1
        "TEST_ESTEID2018_ASiC-E_XAdES_LTA+LTA.sce" | 2
        "TEST_ESTEID2018_ASiC-E_CAdES_LTA.sce"     | 1
    }

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-E with archive timestamped signature, then archiveTimeStamps info is reported correctly"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce")).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX + "signatures[0].info")
                .body("archiveTimeStamps.size()", is(1))

                .body("archiveTimeStamps[0].signedTime", is("2024-09-13T14:14:47Z"))
                .body("archiveTimeStamps[0].country", is("EE"))
                .body("archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("archiveTimeStamps[0].indication", is("PASSED"))
                .body("archiveTimeStamps[0].content", is("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"))
    }

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-E with repeatedly archive timestamped signature, then archiveTimeStamps info is reported correctly"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LTAx2.sce")).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX + "signatures[0].info")
                .body("archiveTimeStamps.size()", is(2))

        // First archive timestamp info
                .body("archiveTimeStamps[0].signedTime", is("2024-09-13T14:14:47Z"))
                .body("archiveTimeStamps[0].country", is("EE"))
                .body("archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("archiveTimeStamps[0].indication", is("PASSED"))
                .body("archiveTimeStamps[0].content", is("MIIGaQYJKoZIhvcNAQcCoIIGWjCCBlYCAQMxDTALBglghkgBZQMEAgEwgeoGCyqGSIb3DQEJEAEEoIHaBIHXMIHUAgEBBgYEAI9nAQEwLzALBglghkgBZQMEAgEEILVrn1FheOLGbm3kQDD7WCBBXxz+cFUa/L6/d2s/n1tvAghRf0n8ziLXuBgPMjAyNDA5MTMxNDE0NDdaMAMCAQGgdqR0MHIxLTArBgNVBAMMJERFTU8gU0sgVElNRVNUQU1QSU5HIEFVVEhPUklUWSAyMDIzRTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUWgggMWMIIDEjCCApigAwIBAgIQM7BQCImkdt18qWDYdbfOtjAKBggqhkjOPQQDAjBlMSAwHgYDVQQDDBdURVNUIG9mIFNLIFRTQSBDQSAyMDIzRTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjMwNjE1MDcxMjA0WhcNMjkwNjE0MDcxMjAzWjByMS0wKwYDVQQDDCRERU1PIFNLIFRJTUVTVEFNUElORyBBVVRIT1JJVFkgMjAyM0UxFzAVBgNVBGEMDk5UUkVFLTEwNzQ3MDEzMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlvbnMgQVMxCzAJBgNVBAYTAkVFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFlmfS6324KQUsz5xSbkG0PxwZfi94mYeuZkculhxkgmIAD3/sSOIoNqRTHg9Jl4tR2VNcMocjLRli474M6SKLqOCARswggEXMB8GA1UdIwQYMBaAFGkForSjh0uOXxhFLdWxlzTPZzu3MG8GCCsGAQUFBwEBBGMwYTA7BggrBgEFBQcwAoYvaHR0cHM6Ly9jLnNrLmVlL1RFU1Rfb2ZfU0tfVFNBX0NBXzIwMjNFLmRlci5jcnQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9kZW1vLnNrLmVlL29jc3AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwPAYDVR0fBDUwMzAxoC+gLYYraHR0cHM6Ly9jLnNrLmVlL1RFU1Rfb2ZfU0tfVFNBX0NBXzIwMjNFLmNybDAdBgNVHQ4EFgQUPmDgaUB5qWkDeoNoc62C/QKk93YwDgYDVR0PAQH/BAQDAgbAMAoGCCqGSM49BAMCA2gAMGUCMAK0/sP+jVQFNFakD4SeVy9xAZovv7T9WuaKfztgdefdJNMm8gaS9HpAa/wwVvnjqQIxAOU2sPULdJMNC6qw563eDasMq9fRUnAf17+/I+byednRNGW3SGYtyGWN8IKKBut4lDGCAjkwggI1AgEBMHkwZTEgMB4GA1UEAwwXVEVTVCBvZiBTSyBUU0EgQ0EgMjAyM0UxFzAVBgNVBGEMDk5UUkVFLTEwNzQ3MDEzMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlvbnMgQVMxCzAJBgNVBAYTAkVFAhAzsFAIiaR23XypYNh1t862MAsGCWCGSAFlAwQCAaCCAVIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDA5MTMxNDE0NDdaMCgGCSqGSIb3DQEJNDEbMBkwCwYJYIZIAWUDBAIBoQoGCCqGSM49BAMCMC8GCSqGSIb3DQEJBDEiBCAcFDaMg3RL5ZZAlGTJuHFPBZ9ZjlmonzRsQHB2FEt7uzCBugYLKoZIhvcNAQkQAi8xgaowgacwgaQwgaEEIH5oXa27s3kdak1EefuhSEpRUqhLmUIcHSEKiNe56Ba6MH0waaRnMGUxIDAeBgNVBAMMF1RFU1Qgb2YgU0sgVFNBIENBIDIwMjNFMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMQswCQYDVQQGEwJFRQIQM7BQCImkdt18qWDYdbfOtjAKBggqhkjOPQQDAgRGMEQCIAOeDvwb2HGXdajcPuZEt1vRs7w3KM2IPa+KYf1I6Ye5AiAFfKus72xjUUWYyxlAPf3FrgPt9GucRQqPGTzPndEGEw=="))

        // Second archive timestamp info
                .body("archiveTimeStamps[1].signedTime", is("2025-04-11T13:53:26Z"))
                .body("archiveTimeStamps[1].country", is("EE"))
                .body("archiveTimeStamps[1].signedBy", is("DEMO SK TIMESTAMPING UNIT 2025E"))
                .body("archiveTimeStamps[1].indication", is("PASSED"))
                .body("archiveTimeStamps[1].content", is("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"))
    }

    @Description("Simple report includes archive timestamp info")
    def "Given ASiC-E with signature with invalid archive timestamp, then archiveTimeStamps info is reported correctly"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2xLTA-SK+Entrust.asice")).then()
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .rootPath(VALIDATION_CONCLUSION_PREFIX + "signatures[0].info")
                .body("archiveTimeStamps.size()", is(2))

        // First (valid) archive timestamp info
                .body("archiveTimeStamps[0].signedTime", is("2025-04-11T15:11:03Z"))
                .body("archiveTimeStamps[0].country", is("EE"))
                .body("archiveTimeStamps[0].signedBy", is("DEMO SK TIMESTAMPING UNIT 2025E"))
                .body("archiveTimeStamps[0].indication", is("PASSED"))
                .body("archiveTimeStamps[0].content", is("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"))

        // Second (invalid) archive timestamp info
                .body("archiveTimeStamps[1].signedTime", is("2025-04-11T15:11:04Z"))
                .body("archiveTimeStamps[1].country", is("US"))
                .body("archiveTimeStamps[1].signedBy", is("Entrust Timestamp Authority - TSA1"))
                .body("archiveTimeStamps[1].indication", is("INDETERMINATE"))
                .body("archiveTimeStamps[1].subIndication", is("NO_CERTIFICATE_CHAIN_FOUND"))
                .body("archiveTimeStamps[1].content", is("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"))
    }
}
