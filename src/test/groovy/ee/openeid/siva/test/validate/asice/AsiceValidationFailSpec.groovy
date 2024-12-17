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
import io.qameta.allure.Link
import org.apache.http.HttpStatus
import spock.lang.Ignore

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class AsiceValidationFailSpec extends GenericSpecification {

    @Description("Bdoc with single invalid signature")
    def "asiceInvalidSingleSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidLiveSignature.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].signedBy", is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("38211015222"))
                .body("signatures[0].subIndication", is(SUB_INDICATION_HASH_FAILURE))
                .body("signatures[0].info.bestSignatureTime", is("2016-10-11T09:36:10Z"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, REFERENCE_DATA_NOT_INTACT))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice with multiple invalid signatures")
    def "asiceInvalidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidMultipleSignatures.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", is("2016-06-21T21:33:10Z"))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[1].subIndication", is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[1].info.bestSignatureTime", is("2016-06-21T21:38:50Z"))
                .body("signatures[1].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(2))
    }

    @Description("Asice with multiple signatures both valid and invalid")
    def "asiceInvalidAndValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidAndValidSignatures.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].info.bestSignatureTime", is("2016-06-21T21:38:50Z"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", is("2016-06-21T21:33:10Z"))
                .body("signatures[0].errors.content", hasItems(TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(2))
    }

    @Description("Asice with no signatures")
    def "asiceNoSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerNoSignature.asice"))
                .then()
                .body("validationReport.validationConclusion.signatureForm", is(ContainerFormat.ASiC_E))
                .body("validationReport.validationConclusion.validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validationReport.validationConclusion.validSignaturesCount", is(0))
                .body("validationReport.validationConclusion.signaturesCount", is(0))
    }

    @Description("Wrong signature timestamp")
    def "asiceInvalidTimeStampDontMatchSigValue"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-02_23634_TS_wrong_SignatureValue.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", is("2015-11-13T11:15:36Z"))
                .body("signatures[0].errors.content", hasItems(TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice No non-repudiation key usage value in the certificate, verification of AdES signature level")
    def "asiceInvalidNonRepudiationKey"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-I-43.asice", SignaturePolicy.POLICY_3, ReportType.SIMPLE))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureLevel", is(SignatureLevel.INDETERMINATE_UNKNOWN))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_CHAIN_CONSTRAINTS_FAILURE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, NOT_EXPECTED_KEY_USAGE))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice signers certificate does not have non-repudiation value in the certificates key usage field and it does not contain the QC and SSCD compliance information.")
    def "asiceInvalidNonRepudiationKeyNoComplianceInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-I-26.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_CHAIN_CONSTRAINTS_FAILURE))
                .body("signatures[0].errors.content", contains(
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        NOT_EXPECTED_KEY_USAGE,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", is(0))
    }

    @Description("OCSP certificate is not trusted")
    def "asiceNotTrustedOcspCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("TM-01_bdoc21-unknown-resp.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_CERTIFICATE_CHAIN_GENERAL_FAILURE))
                .body("signatures[0].errors.content", hasItems(VALID_VALIDATION_PROCESS_ERROR_VALUE_5, REVOCATION_NOT_TRUSTED))
                .body("signatures[0].signedBy", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEPzCCAyegAwIBAgIQH0FobucEcidPGVN0HUUgATANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("DemoCA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDmjCCAoKgAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwgZkxCz"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice TSA certificate is not trusted")
    def "asiceNotTrustedTsaCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-05_23634_TS_unknown_TSA.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(TS_NOT_TRUSTED))
                .body("signatures[0].certificates.size()", is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("Time Stamp Authority Server"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIG2jCCBMKgAwIBAgIBCDANBgkqhkiG9w0BAQUFADCBpDELMA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice OCSP response status is revoked")
    def "asiceTsOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-R-25.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_REVOKED_NO_POE))
                .body("signatures[0].info.bestSignatureTime", is("2014-11-07T11:43:06Z"))
                .body("signatures[0].errors.content", hasItems(PAST_SIG_VALIDATION_NOT_CONCLUSIVE))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice difference between OCSP and time-stamp issuing times is more than 24 hours")
    def "asiceOcspAndTsDifferenceOver24H"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-20.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].info.bestSignatureTime", is("2014-11-07T13:18:01Z"))
                .body("signatures[0].errors.content", hasItems(REVOCATION_NOT_FRESH))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice unsigned data files in the container")
    def "asiceUnsignedDataFiles"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-34.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].warnings.content", hasItems(VALID_VALIDATION_PROCESS_VALUE_35))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice SignatureValue does not correspond to the SignedInfo block")
    def "asiceSignatureValueDoNotCorrespondToSignedInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("REF-19_bdoc21-no-sig-asn1-pref.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice Baseline-BES file")
    def "asiceBaselineBesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("signWithIdCard_d4j_1.0.4_BES.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, SIG_UNEXPECTED_FORMAT))
                .body("signatures[0].signedBy", is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEojCCA4qgAwIBAgIQPKphkF8jscxRrFRhBsxlhjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Description("Asice Baseline-EPES file")
    def "asiceBaselineEpesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-04_kehtivuskinnituset.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItems(SIG_UNEXPECTED_FORMAT))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIE/TCCA+WgAwIBAgIQJw9uhQnKff9RdnVKwzk1OzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice signers certificate is not trusted")
    def "asiceSignersCertNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SS-4_teadmataCA.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(SIG_NOT_TRUSTED, CERT_PATH_NOT_TRUSTED))
                .body("signatures[0].signedBy", is("signer1"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("libdigidocpp Inter"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIICCTCCAXKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADAnMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice OCSP response status is revoked")
    def "asiceTmOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-15_revoked.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_REVOKED_NO_POE))
                .body("signatures[0].info.bestSignatureTime", is("2013-10-11T11:27:19Z"))
                .body("signatures[0].errors.content", hasItems(PAST_SIG_VALIDATION_NOT_CONCLUSIVE))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice OCSP response status is unknown")
    def "asiceTmOcspStatusUnknown"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-16_unknown.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(REVOCATION_UNKNOWN))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice signed data file has been removed from the container")
    def "asiceSignedFileRemoved"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("KS-21_fileeemaldatud.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_SIGNED_DATA_NOT_FOUND))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_FOUND))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice no files in container")
    def "asiceNoFilesInContainer"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequestForDDS("KS-02_tyhi.bdoc", null, null))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", hasSize(2))
    }

    @Description("Asice signed data file(s) don't match the hash values in reference elements")
    def "asiceDataFilesDontMatchHash"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("REF-14_filesisumuudetud.4.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_HASH_FAILURE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_INTACT))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice Baseline-T signature")
    def "asiceBaselineTSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-06_23634_TS_missing_OCSP.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_NOT_FOUND))
                .body("signatures[0].signedBy", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("tsa01.quovadisglobal.com"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIGOzCCBSOgAwIBAgIUe6m/OP/GwmsrkHR8Mz8LJoNedfgwDQ"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Ignore("Missing test file")
    //TODO: test file is needed where certificate expiration end is before the OCSP produced at time
    @Description("Asice certificate's validity time is not in the period of OCSP producedAt time")
    def "asiceCertificateValidityOutOfOcspRange"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItem(SIG_CREATED_WITH_EXP_CERT))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("BDoc with invalid signature, no signing certificate found")
    def "asiceInvalidSignatureNoSigningCertificateFound"() {
        expect:
        String fileName = "TM-invalid-sig-no-sign-cert.asice"
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signedBy", emptyOrNullString())
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_T))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is(SUB_INDICATION_NO_SIGNING_CERTIFICATE_FOUND))
                .body("signatures[0].claimedSigningTime", is("2013-10-11T11:47:40Z"))
                .body("signatures[0].errors.content", hasItems(VALID_VALIDATION_PROCESS_ERROR_VALUE_9, SIG_NO_CANDIDATE))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
                .body("validatedDocument.filename", is(fileName))
    }

    @Description("BDoc with invalid signature, signed with expired certificate")
    def "asiceSignedWithExpiredCertificate"() {
        expect:
        String fileName = "IB-5987_signed_with_expired_certificate.asice"
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_B))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].claimedSigningTime", is("2016-08-01T13:07:13Z"))
                .body("signatures[0].errors.content", hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_10))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
                .body("validatedDocument.filename", is(fileName))
    }

    @Description("Bdoc signed properties element missing")
    def "bdocTimemarkSignedPropertiesMissing"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-03_bdoc21-TS-no-signedpropref.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is("XAdES_LT"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].errors.content", hasItem(SIG_QUALIFYING_PROPERTY_MISSING))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice LT signature signed with expired AIA OCSP certificate")
    def "asiceLtSignatureSignedWithExpiredAiaOCSP"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("esteid2018signerAiaOcspLT.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_5))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice LTA signature signed with expired AIA OCSP certificate")
    def "asiceLtaSignatureSignedWithExpiredAiaOCSP"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("esteid2018signerAiaOcspLTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].errors.content", hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_5))
                .body("validSignaturesCount", is(0))
    }

    @Description("Asice simple/batchsignature/attachment xroad document")
    def "asiceSimpleXroadDocumentShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(filename, SignaturePolicy.POLICY_3))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].signatureFormat", is("XML_NOT_ETSI"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_FORMAT_FAILURE))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("70006317"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("Riigi Infosüsteemi Amet"))
                .body("signatures[0].errors.content", hasItems(SIG_UNEXPECTED_FORMAT))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))

        where:
        filetype         | filename
        "simple"         | "xroad-simple.asice"
        "batchsignature" | "xroad-batchsignature.asice"
        "attachment"     | "xroad-attachment.asice"
    }
}
