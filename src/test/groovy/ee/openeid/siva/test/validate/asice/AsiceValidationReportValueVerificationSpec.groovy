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

package ee.openeid.siva.test.validate.asice

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import org.hamcrest.Matchers
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.getCERT_VALIDATION_NOT_CONCLUSIVE
import static ee.openeid.siva.test.TestData.getVALIDATION_CONCLUSION_PREFIX
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath

class AsiceValidationReportValueVerificationSpec extends GenericSpecification {

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT_TM, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtTmSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TwoValidTmSignaturesWithRolesAndProductionPlace.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("id-2d1a98a8173d01473aa7e88bc74b361a"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.givenName", Matchers.is("MARI-LIIS"))
                .body("signatures[0].subjectDistinguishedName.surname", Matchers.is("MÄNNIK"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", Matchers.emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", Matchers.is("test.txt"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2020-05-29T08:19:25Z"))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIMebaUX4S1RLE7lcDJ0LxdLQQBgFsGxID+wzbAPvz8Ti"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2020-05-29T08:19:27Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", Matchers.is("Signing as king of signers"))
                .body("signatures[0].info.signerRole[1].claimedRole", Matchers.is("Second role"))
                .body("signatures[0].info.signatureProductionPlace.countryName", Matchers.is("Elbonia"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", Matchers.is("Harju"))
                .body("signatures[0].info.signatureProductionPlace.city", Matchers.is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", Matchers.is("32323"))
                .body("signatures[0].info.timestampCreationTime", Matchers.emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2020-05-29T08:19:27Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIGHjCCBAagAwIBAgIQNcO4eO0xcsNbIk36aVrDqjANBgkqhk"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("TwoValidTmSignaturesWithRolesAndProductionPlace.bdoc"))
                .body("validSignaturesCount", Matchers.is(2))
                .body("signaturesCount", Matchers.is(2))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validTsSignatureWithRolesAndProductionPlace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("id-7022c18f415891f9cb9124927ab14cfb"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("PNOEE-38001085718"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].subjectDistinguishedName.givenName", Matchers.is("JAAK-KRISTJAN"))
                .body("signatures[0].subjectDistinguishedName.surname", Matchers.is("JÕEORG"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", Matchers.emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", Matchers.is("test.txt"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FULL"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Full document"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2020-05-29T09:34:56Z"))
                .body("signatures[0].warnings.content", Matchers.emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIB00XgQZ74rCQz13RlPDKtFVtGiUX01R5rTbhkZZKv0M"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2020-05-29T09:34:58Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", Matchers.is("First role"))
                .body("signatures[0].info.signerRole[1].claimedRole", Matchers.is("Second role"))
                .body("signatures[0].info.signatureProductionPlace.countryName", Matchers.is("Some country"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", Matchers.is("ÕÄLnül23#&()"))
                .body("signatures[0].info.signatureProductionPlace.city", Matchers.is("City with spaces"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", Matchers.is("123456789"))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2020-05-29T09:35:00Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.is("2020-05-29T09:34:58Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIID6jCCA02gAwIBAgIQR+qcVFxYF1pcSy/QGEnMVjAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("TEST of ESTEID2018"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFfDCCBN2gAwIBAgIQNhjzSfd2UEpbkO14EY4ORTAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("DEMO of SK TSA 2014"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEFTCCAv2gAwIBAgIQTqz7bCP8W45UBZa7tztTTDANBgkqhk"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("validTsSignatureWithRolesAndProductionPlace.asice"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT, QES, FullSignatureScope")
    def "bdocCorrectValuesArePresentValidLtSignatureAdesWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S0"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subIndication", Matchers.emptyOrNullString())
                .body("signatures[0].errors", Matchers.emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", Matchers.is("build.xml"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2014-07-11T14:10:07Z"))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEINHGGgGzXqzGfN2J6olA6VaXSeCG1PRBGrmG4wxQYf7A"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2011-10-15T14:59:35Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2011-10-15T14:59:35Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("23154_test1-old-sig-sigat-NOK-prodat-OK-1.bdoc"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("Verification of values in Validation Report XAdES_BASELINE_LT-TM, AdESqc")
    def "bdocCorrectValuesArePresentInvalidLtSignatureAdesqc"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("testAdesQCInvalid.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S1510667783001"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.NOT_ADES_QC))
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("HASH_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signatureScopes[0].name", Matchers.is("test.pdf"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FULL"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Full document"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2017-11-14T13:56:23Z"))
                .body("signatures[0].warnings.content", Matchers.hasItem("The private key does not reside in a QSCD at issuance time!"))
                .body("signatures[0].warnings.content", Matchers.hasItem("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings.content", Matchers.hasItem("The signature/seal is not a valid AdES digital signature!"))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.emptyOrNullString())
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2017-11-14T13:56:34Z"))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2017-11-14T13:56:35Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.is("2017-11-14T13:56:34Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("NURM,AARE,PNOEE-38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIHkDCCBXigAwIBAgIQE2MaQOlx//NYkuLVlIRaIzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("EID-SK 2016"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIG4jCCBcqgAwIBAgIQO4A6a2nBKoxXxVAFMRvE2jANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("testAdesQCInvalid.asice"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("JSON structure has all elements (Bdoc valid multiple signatures)")
    def "bdocAllElementsArePresentValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Baltic MoU digital signing_EST_LT_LV.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S0"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("MICHAL,KRISTEN,37507120348"))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors", Matchers.emptyOrNullString())
                .body("signatures[0].signatureScopes[0].name", Matchers.is("Baltic MoU digital signing_04112015.docx"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Digest of the document content"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2015-11-04T10:24:11Z"))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEINiaR8aBDIPiXK/fiPb7fe3pWaBaEKzILvjnZVppopPy"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2015-11-04T10:24:20Z"))
                .body("signatures[0].info.timestampCreationTime", Matchers.emptyOrNullString())
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2015-11-04T10:24:20Z"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MICHAL,KRISTEN,37507120348"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEoTCCA4mgAwIBAgIQXESH+ckjJK1SC2r9DcQrDzANBgkqhk"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("Baltic MoU digital signing_EST_LT_LV.bdoc"))
                .body("validSignaturesCount", Matchers.is(3))
                .body("signaturesCount", Matchers.is(3))
    }

    @Ignore
    //TODO: needs investigation why the signature is determined as XAdES_BASELINE_T not as XAdES_BASELINE_LT_TM
    @Description("JSON structure has all elements (Bdoc indeterminate status)")
    def "bdocAllElementsArePresentIndeterminateSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SS-4_teadmataCA.4.asice", SignaturePolicy.POLICY_3, ReportType.SIMPLE))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].id", Matchers.is("S0"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", Matchers.is("signer1"))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", Matchers.is("The certificate path is not trusted!"))
                .body("signatures[0].errors[1].content", Matchers.is("The result of the LTV validation process is not acceptable to continue the process!"))
                .body("signatures[0].signatureScopes[0].name", Matchers.is("test1.txt"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FULL"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Full document"))
                .body("signatures[0].claimedSigningTime", Matchers.is("2013-10-11T08:15:47Z"))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.emptyOrNullString())
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is("libdigidocpp Inter"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIICCTCCAXKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADAnMQswCQ"))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("SS-4_teadmataCA.4.asice"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("Bdoc report with no signatures")
    def "bdocNoSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerNoSignature.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures", Matchers.emptyOrNullString())
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", Matchers.is("BdocContainerNoSignature.bdoc"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(0))
    }

    @Description("Bdoc with LT_TM, LT & LTA signature - timeAssertionMessageImprints in mixed container are reported correctly")
    def "bdocMixedSignaturesContainerCorrectTimeAssertionMessageImprint"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIGzgagluBCVuUgrnT6C5BmSAXBxuuxvlAN7epdGqHP0/"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIBcwYgTTCv5dabbTMJENwex0W1UHxP2OnhiwIcDE89RE"))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIOcfB5FibacEVizcnKhNisrfXU1QyXFzrVGjCQQdntiB"))
    }

    @Description("Asice with LT_TM, LT & LTA signature - timeAssertionMessageImprints in mixed container are reported correctly")
    def "asiceMixedSignaturesContainerCorrectTimeAssertionMessageImprint"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIGzgagluBCVuUgrnT6C5BmSAXBxuuxvlAN7epdGqHP0/"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIBcwYgTTCv5dabbTMJENwex0W1UHxP2OnhiwIcDE89RE"))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.timeAssertionMessageImprint", Matchers.is("MDEwDQYJYIZIAWUDBAIBBQAEIOcfB5FibacEVizcnKhNisrfXU1QyXFzrVGjCQQdntiB"))

    }

    @Ignore("SIVA-365")
    @Description("Bdoc with B & LT_TM mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "asiceMixedSignaturesSameCertificateContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:15:43Z"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:31:37Z"))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:38:11Z"))
    }

    @Description("Bdoc with LT_TM, LT & LTA signature, LT & LTA with same certificate - ocspResponseCreationTimes in mixed container are reported correctly")
    def "bdocMixedSignaturesSameCertificateContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:15:43Z"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:31:37Z"))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].info.ocspResponseCreationTime", Matchers.is("2021-01-29T14:38:11Z"))
    }

    @Description("Asice with LT & T mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "asiceMixedSignaturesContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2_signatures_T_LT.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].info", Matchers.not(Matchers.hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2022-08-25T09:05:10Z"))
    }

    @Description("Bdoc with LT-TM & B mixed signatures - ocspResponseCreationTimes in mixed container are reported correctly")
    def "bdocMixedSignaturesContainerCorrectOcspResponseCreationTime"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2_signatures_B_TM.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body(matchesJsonSchemaInClasspath("SimpleReportSchema.json"))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_B_EPES))
                .body("signatures[0].info", Matchers.not(Matchers.hasKey("ocspResponseCreationTime")))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].info.ocspResponseCreationTime", Matchers.is("2022-08-25T12:22:37Z"))
    }

    @Description("Filtering out warning \"The trusted certificate does not match the trust service!\" in Simple Report")
    def "bdocFilterTrustServiceWarningSimpleReport"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validTsSignatureWithRolesAndProductionPlace.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", Matchers.not(Matchers.hasItem(DssMessage.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.message)))
                .body("signatures[0].warnings.content", Matchers.emptyOrNullString())
    }

    @Description("Filtering out warning \"The certificate is not related to a granted status at time-stamp lowest POE time!\" in Simple Report")
    def "bdocFilterLowestPoeTimeErrorSimpleReport"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4183_3.4kaart_RSA2047_TS.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].errors.content", Matchers.not(Matchers.hasItem(DssMessage.QUAL_HAS_GRANTED_AT_ANS.message)))
                .body("signatures[0].errors.content", Matchers.emptyOrNullString())
    }
}
