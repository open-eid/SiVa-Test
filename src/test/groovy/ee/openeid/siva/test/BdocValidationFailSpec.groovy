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

package ee.openeid.siva.test

import ee.openeid.siva.common.Constants
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.apache.http.HttpStatus
import org.hamcrest.Matchers

import static ee.openeid.siva.integrationtest.TestData.*
import static org.hamcrest.Matchers.emptyOrNullString

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class BdocValidationFailSpec extends GenericSpecification {

    @Description("Bdoc with single invalid signature")
    def "bdocInvalidSingleSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-3960_bdoc2.1_TSA_SignatureValue_altered.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIFHTCCBAWgAwIBAgIQDq1SanUB71xO+wbqIO72rDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc with multiple invalid signatures")
    def "bdocInvalidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocMultipleSignaturesInvalid.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[2].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signaturesCount", Matchers.is(3))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc with multiple signatures both valid and invalid")
    def "bdocInvalidAndValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocMultipleSignaturesMixedWithValidAndInvalid.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[2].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[3].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[3].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[3].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[3].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(5))
                .body("validSignaturesCount", Matchers.is(3))

    }

    @Description("Bdoc with no signatures")
    def "bdocNoSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BdocContainerNoSignature.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validSignaturesCount", Matchers.is(0))
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings[0].content", Matchers.is(Constants.TEST_ENV_VALIDATION_WARNING))
    }

    @Description("Wrong signature timestamp")
    def "bdocInvalidTimeStampDontMatchSigValue"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-02_23634_TS_wrong_SignatureValue.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2015-11-13T11:15:36Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(VALID_VALIDATION_PROCESS_ERROR_VALUE_9, SIG_INVALID_TS))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice No non-repudiation key usage value in the certificate, verification of AdES signature level")
    def "bdocInvalidNonRepudiationKey"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-I-43.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is("CHAIN_CONSTRAINTS_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, NOT_EXPECTED_KEY_USAGE))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice signers certificate does not have non-repudiation value in the certificates key usage field and it does not contain the QC and SSCD compliance information.")
    def "bdocInvalidNonRepudiationKeyNoComplianceInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-I-26.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is("CHAIN_CONSTRAINTS_FAILURE"))
                .body("signatures[0].errors.content", Matchers.contains(
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        NOT_EXPECTED_KEY_USAGE,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc OCSP certificate is not trusted")
    def "bdocNotTrustedOcspCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-01_bdoc21-unknown-resp.bdoc", SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("FORMAT_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_NOT_TRUSTED))
                .body("signatures[0].signedBy", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEPzCCAyegAwIBAgIQH0FobucEcidPGVN0HUUgATANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("DemoCA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIDmjCCAoKgAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwgZkxCz"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice TSA certificate is not trusted")
    def "bdocNotTrustedTsaCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-05_23634_TS_unknown_TSA.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-05-19T10:45:19Z"))
                .body("signatures[0].errors.content", Matchers.hasItems("Signature has an invalid timestamp"))
                .body("signatures[0].signedBy", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("Time Stamp Authority Server"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIG2jCCBMKgAwIBAgIBCDANBgkqhkiG9w0BAQUFADCBpDELMA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice OCSP response status is revoked")
    def "bdocTsOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-R-25.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is("REVOKED_NO_POE"))
                .body("signatures[0].errors.content", Matchers.hasItems("The past signature validation is not conclusive!"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice difference between OCSP and time-stamp issuing times is more than 24 hours")
    def "bdocOcspAndTsDifferenceOver24H"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-20.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", Matchers.is("The difference between the OCSP response time and the signature timestamp is too large"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc different data file mime-type values in signatures.xml and manifest.xml files")
    def "bdocDifferentDataFileInSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23613_TM_wrong-manifest-mimetype.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", Matchers.hasItems("Manifest file has an entry for file <test.txt> with mimetype <application/binary> but the signature file for signature S0 indicates the mimetype is <application/octet-stream>"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc SignatureValue does not correspond to the SignedInfo block")
    def "bdocSignatureValueDoNotCorrespondToSignedInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-19_bdoc21-no-sig-asn1-pref.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc Baseline-BES file")
    def "bdocBaselineBesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("signWithIdCard_d4j_1.0.4_BES.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_B_BES))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.notNullValue())
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.notNullValue())
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signedBy", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.size()", Matchers.is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEojCCA4qgAwIBAgIQPKphkF8jscxRrFRhBsxlhjANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("Bdoc Baseline-EPES file")
    def "bdocBaselineEpesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-04_kehtivuskinnituset.4.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_B_EPES))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", Matchers.is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIE/TCCA+WgAwIBAgIQJw9uhQnKff9RdnVKwzk1OzANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc signers certificate is not trusted")
    def "bdocSignersCertNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("SS-4_teadmataCA.4.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2013-10-11T08:15:47Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(SIG_NOT_TRUSTED, CERT_PATH_NOT_TRUSTED))
                .body("signatures[0].signedBy", Matchers.is("signer1"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc OCSP response status is revoked")
    def "bdocTmOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-15_revoked.4.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is("REVOKED_NO_POE"))
                .body("signatures[0].errors.content", Matchers.hasItems("The past signature validation is not conclusive!"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc OCSP response status is unknown")
    def "bdocTmOcspStatusUnknown"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TM-16_unknown.4.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_UNKNOWN))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc signed data file has been removed from the container")
    def "bdocSignedFileRemoved"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequestForDD4J("KS-21_fileeemaldatud.4.asice", null, null))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE))
    }

    @Description("Bdoc no files in container")
    def "bdocNoFilesInContainer"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("KS-02_tyhi.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", Matchers.hasSize(2))
    }

    @Description("Bdoc wrong nonce")
    def "bdocWrongOcspNonce"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-10_noncevale.4.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", Matchers.hasItem("OCSP nonce is invalid"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc signed data file(s) don't match the hash values in reference elements")
    def "bdocDataFilesDontMatchHash"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-14_filesisumuudetud.4.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", Matchers.is("HASH_FAILURE"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_INTACT))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Asice Baseline-T signature")
    def "bdocBaselineTSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("TS-06_23634_TS_missing_OCSP.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-05-19T10:48:04Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_NOT_FOUND))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("tsa01.quovadisglobal.com"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIGOzCCBSOgAwIBAgIUe6m/OP/GwmsrkHR8Mz8LJoNedfgwDQ"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc OCSP response is not the one expected")
    def "bdocWrongSignersCertInOcspResponse"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23608-bdoc21-TM-ocsp-bad-nonce.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].info.bestSignatureTime", emptyOrNullString())
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", Matchers.hasItem("OCSP nonce is invalid"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc certificate's validity time is not in the period of OCSP producedAt time")
    def "bdocCertificateValidityOutOfOcspRange"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23154_test1-old-sig-sigat-OK-prodat-NOK-1.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.contains(
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        VALID_VALIDATION_PROCESS_ERROR_VALUE_5,
                        REVOCATION_NOT_CONSISTENT,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc BDOC-1.0 version container")
    def "bdocOldNotSupportedVersion"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequest("BDOC-1.0.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].key", Matchers.is("document"))
                .body("requestErrors[0].message", Matchers.is(DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE))
    }

    @Description("Asice unsigned data files in the container")
    def "asiceUnsignedDataFiles"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-34.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors[0].content", Matchers.is("Manifest file has an entry for file <unsigned.txt> with mimetype <text/plain> but the signature file for signature S0 does not have an entry for this file"))
                .body("signatures[0].errors[1].content", Matchers.is("Container contains a file named <unsigned.txt> which is not found in the signature file"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(0))

    }

    @Description("Bdoc signed properties element missing")
    def "bdocTimemarkSignedPropertiesMissing"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-03_bdoc21-TM-no-signedpropref.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", Matchers.hasItem(SIG_QUALIFYING_PROPERTY_MISSING))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Description("Bdoc OCSP certificate in both signature and OCSP token")
    def "bdocTimemarkNoOcspCertificate"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("NoOcspCertificateAnywhere.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].errors.content", Matchers.hasItem("OCSP Responder does not meet TM requirements"))
                .body("validSignaturesCount", Matchers.is(0))
    }

    @Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
    @Description("Asice Baseline-LTA file")
    def "bdocBaselineLtaProfileValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LTA-V-24.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", Matchers.is("TOTAL-FAILED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-10-30T18:50:35Z"))
                .body("signatures[0].signedBy", Matchers.is("METSMA,RAUL,38207162766"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("METSMA,RAUL,38207162766"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEmzCCA4OgAwIBAgIQFQe7NKtE06tRSY1vHfPijjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("BalTstamp QTSA TSU2"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEtzCCA5+gAwIBAgIKFg5NNQAAAAADhzANBgkqhkiG9w0BAQ"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(0))
    }
}
