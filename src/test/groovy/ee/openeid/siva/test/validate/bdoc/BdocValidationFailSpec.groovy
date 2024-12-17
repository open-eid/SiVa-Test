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

package ee.openeid.siva.test.validate.bdoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.qameta.allure.Story
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class BdocValidationFailSpec extends GenericSpecification {

    @Description("Bdoc with single invalid signature")
    def "bdocInvalidSingleSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-3960_bdoc2.1_TSA_SignatureValue_altered.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIFHTCCBAWgAwIBAgIQDq1SanUB71xO+wbqIO72rDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc with multiple invalid signatures")
    def "bdocInvalidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocMultipleSignaturesInvalid.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[2].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", is(3))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc with multiple signatures both valid and invalid")
    def "bdocInvalidAndValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocMultipleSignaturesMixedWithValidAndInvalid.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[2].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[2].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[3].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[3].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[3].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[3].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(5))
                .body("validSignaturesCount", is(3))

    }

    @Description("Bdoc with no signatures")
    def "bdocNoSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerNoSignature.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validSignaturesCount", is(0))
                .body("validationWarnings", hasSize(1))
                .body("validationWarnings[0].content", is(TestData.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Wrong signature timestamp")
    def "bdocInvalidTimeStampDontMatchSigValue"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-02_23634_TS_wrong_SignatureValue.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].info.bestSignatureTime", is("2015-11-13T11:15:36Z"))
                .body("signatures[0].errors.content", hasItems(TestData.VALID_VALIDATION_PROCESS_ERROR_VALUE_9, TestData.SIG_INVALID_TS))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice No non-repudiation key usage value in the certificate, verification of AdES signature level")
    def "bdocInvalidNonRepudiationKey"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-I-43.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("CHAIN_CONSTRAINTS_FAILURE"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.NOT_EXPECTED_KEY_USAGE))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice signers certificate does not have non-repudiation value in the certificates key usage field and it does not contain the QC and SSCD compliance information.")
    def "bdocInvalidNonRepudiationKeyNoComplianceInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-I-26.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("CHAIN_CONSTRAINTS_FAILURE"))
                .body("signatures[0].errors.content", contains(
                        TestData.CERT_VALIDATION_NOT_CONCLUSIVE,
                        TestData.NOT_EXPECTED_KEY_USAGE,
                        TestData.CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc OCSP certificate is not trusted")
    def "bdocNotTrustedOcspCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-01_bdoc21-unknown-resp.bdoc", SignaturePolicy.POLICY_3))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("FORMAT_FAILURE"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_NOT_TRUSTED))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEPzCCAyegAwIBAgIQH0FobucEcidPGVN0HUUgATANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("DemoCA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDmjCCAoKgAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwgZkxCz"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice TSA certificate is not trusted")
    def "bdocNotTrustedTsaCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-05_23634_TS_unknown_TSA.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].info.bestSignatureTime", is("2014-05-19T10:45:19Z"))
                .body("signatures[0].errors.content", hasItems("Signature has an invalid timestamp"))
                .body("signatures[0].signedBy", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("Time Stamp Authority Server"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIG2jCCBMKgAwIBAgIBCDANBgkqhkiG9w0BAQUFADCBpDELMA"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice OCSP response status is revoked")
    def "bdocTsOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-R-25.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("REVOKED_NO_POE"))
                .body("signatures[0].errors.content", hasItems("The past signature validation is not conclusive!"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice difference between OCSP and time-stamp issuing times is more than 24 hours")
    def "bdocOcspAndTsDifferenceOver24H"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-20.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", is("The difference between the OCSP response time and the signature timestamp is too large"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc different data file mime-type values in signatures.xml and manifest.xml files")
    def "bdocDifferentDataFileInSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23613_TM_wrong-manifest-mimetype.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItems("Manifest file has an entry for file <test.txt> with mimetype <application/binary> but the signature file for signature S0 indicates the mimetype is <application/octet-stream>"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc SignatureValue does not correspond to the SignedInfo block")
    def "bdocSignatureValueDoNotCorrespondToSignedInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-19_bdoc21-no-sig-asn1-pref.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc Baseline-BES file")
    def "bdocBaselineBesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("signWithIdCard_d4j_1.0.4_BES.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B_BES))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", notNullValue())
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signedBy", is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEojCCA4qgAwIBAgIQPKphkF8jscxRrFRhBsxlhjANBgkqhk"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("Bdoc Baseline-EPES file")
    def "bdocBaselineEpesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-04_kehtivuskinnituset.4.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B_EPES))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIE/TCCA+WgAwIBAgIQJw9uhQnKff9RdnVKwzk1OzANBgkqhk"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc signers certificate is not trusted")
    def "bdocSignersCertNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("SS-4_teadmataCA.4.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", is("2013-10-11T08:15:47Z"))
                .body("signatures[0].errors.content", hasItems(TestData.SIG_NOT_TRUSTED, TestData.CERT_PATH_NOT_TRUSTED))
                .body("signatures[0].signedBy", is("signer1"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc OCSP response status is revoked")
    def "bdocTmOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-15_revoked.4.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("REVOKED_NO_POE"))
                .body("signatures[0].errors.content", hasItems("The past signature validation is not conclusive!"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc OCSP response status is unknown")
    def "bdocTmOcspStatusUnknown"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-16_unknown.4.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_UNKNOWN))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc signed data file has been removed from the container")
    def "bdocSignedFileRemoved"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequestForDD4J(
                "KS-21_fileeemaldatud.4.asice", null, null))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Bdoc no files in container")
    def "bdocNoFilesInContainer"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("KS-02_tyhi.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(2))
    }

    @Description("Bdoc wrong nonce")
    def "bdocWrongOcspNonce"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-10_noncevale.4.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItem("OCSP nonce is invalid"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc signed data file(s) don't match the hash values in reference elements")
    def "bdocDataFilesDontMatchHash"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-14_filesisumuudetud.4.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("HASH_FAILURE"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REFERENCE_DATA_NOT_INTACT))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice Baseline-T signature")
    def "bdocBaselineTSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-06_23634_TS_missing_OCSP.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", is("2014-05-19T10:48:04Z"))
                .body("signatures[0].errors.content", hasItems(TestData.CERT_VALIDATION_NOT_CONCLUSIVE, TestData.REVOCATION_NOT_FOUND))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("tsa01.quovadisglobal.com"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIGOzCCBSOgAwIBAgIUe6m/OP/GwmsrkHR8Mz8LJoNedfgwDQ"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc OCSP response is not the one expected")
    def "bdocWrongSignersCertInOcspResponse"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23608-bdoc21-TM-ocsp-bad-nonce.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].info.bestSignatureTime", emptyOrNullString())
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItem("OCSP nonce is invalid"))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc certificate's validity time is not in the period of OCSP producedAt time")
    def "bdocCertificateValidityOutOfOcspRange"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23154_test1-old-sig-sigat-OK-prodat-NOK-1.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", contains(
                        TestData.CERT_VALIDATION_NOT_CONCLUSIVE,
                        TestData.VALID_VALIDATION_PROCESS_ERROR_VALUE_5,
                        TestData.REVOCATION_NOT_CONSISTENT,
                        TestData.CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc BDOC-1.0 version container")
    def "bdocOldNotSupportedVersion"() {
        when:
        Response response = SivaRequests.tryValidate(RequestData.validationRequest("BDOC-1.0.bdoc"))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    @Description("Asice unsigned data files in the container")
    def "asiceUnsignedDataFiles"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-34.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", is("Manifest file has an entry for file <unsigned.txt> with mimetype <text/plain> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors[1].content", is("Container contains a file named <unsigned.txt> which is not found in the signature file"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(0))

    }

    @Description("Bdoc signed properties element missing")
    def "bdocTimemarkSignedPropertiesMissing"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-03_bdoc21-TM-no-signedpropref.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItem(TestData.SIG_QUALIFYING_PROPERTY_MISSING))
                .body("validSignaturesCount", is(0))
    }

    @Description("Bdoc OCSP certificate in both signature and OCSP token")
    def "bdocTimemarkNoOcspCertificate"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("NoOcspCertificateAnywhere.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", hasItem("OCSP Responder does not meet TM requirements"))
                .body("validSignaturesCount", is(0))
    }

    @Story("Only QTST timestamp allowed")
    @Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
    @Description("Bdoc XAdES LTA signature with non-qualified timestamp not allowed")
    def "Bdoc LTA signature with non-qualified timestamps produces correct errors in simple report"() {
        when: "report is requested"
        Response response = SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LTA-V-24.asice"))

        then: "report matches expectation"
        String expected = new String(Utils.readFileFromResources("EE_SER-AEX-B-LTA-V-24ReportBdoc.json"))
        String actual = response.then().extract().asString()
        assertJsonEquals(expected, actual)
    }

    @Description("Signature with BDOC policy should fail validation when extended to LT or LTA profile")
    def "Signature with BDOC policy extended to #comment profile should fail validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(filename))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(signatureProfiles))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItem("Invalid signature format for BDOC policy"))
                .body("validSignaturesCount", is(0))

        where:
        comment | filename                                        | signatureProfiles
  //TODO: SIVA-777      "LT"    | "singleValidSignatureTmPolicyExtendedToLt.sce"  | SignatureFormat.XAdES_BASELINE_LT_TM
        "LTA"   | "singleValidSignatureTmPolicyExtendedToLta.sce" | SignatureFormat.XAdES_BASELINE_LTA
    }
}
