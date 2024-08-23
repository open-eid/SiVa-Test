/*
 * Copyright 2017 - 2024 Riigi Infosüsteemi Amet
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

import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import org.apache.http.HttpStatus
import org.hamcrest.Matchers
import spock.lang.Ignore

import static ee.openeid.siva.integrationtest.TestData.*

class AsiceValidationFailSpec extends GenericSpecification {

    /**
     * TestCaseID: Asice-ValidationFail-1
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common-validation-constraints-polv3-polv4
     * <p>
     * Title: Bdoc with single invalid signature
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: InvalidLiveSignature.asice
     */
    def "asiceInvalidSingleSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidLiveSignature.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("38211015222"))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_HASH_FAILURE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-10-11T09:36:10Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, REFERENCE_DATA_NOT_INTACT))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-2
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice with multiple invalid signatures
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: InvalidMultipleSignatures.bdoc
     */
    def "asiceInvalidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidMultipleSignatures.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-06-21T21:33:10Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[1].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[1].subIndication", Matchers.is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[1].info.bestSignatureTime", Matchers.is("2016-06-21T21:38:50Z"))
                .body("signatures[1].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(2))
    }

    /**
     * TestCaseID: Asice-ValidationFail-3
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice with multiple signatures both valid and invalid
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: InvalidAndValidSignatures.asice
     */
    def "asiceInvalidAndValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("InvalidAndValidSignatures.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[1].indication", Matchers.is(TOTAL_PASSED))
                .body("signatures[1].info.bestSignatureTime", Matchers.is("2016-06-21T21:38:50Z"))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-06-21T21:33:10Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(2))
    }

    /**
     * TestCaseID: Asice-ValidationFail-4
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice with no signatures
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: AsiceContainerNoSignature.asice
     */
    def "asiceNoSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("AsiceContainerNoSignature.asice"))
                .then()
                .body("validationReport.validationConclusion.signatureForm", Matchers.is("ASiC-E"))
                .body("validationReport.validationConclusion.validationLevel", Matchers.is("ARCHIVAL_DATA"))
                .body("validationReport.validationConclusion.validSignaturesCount", Matchers.is(0))
                .body("validationReport.validationConclusion.signaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-5
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Wrong signature timestamp
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TS-02_23634_TS_wrong_SignatureValue.asice
     */
    def "asiceInvalidTimeStampDontMatchSigValue"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-02_23634_TS_wrong_SignatureValue.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2015-11-13T11:15:36Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(TS_MESSAGE_NOT_INTACT, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-6
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice No non-repudiation key usage value in the certificate, verification of AdES signature level
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: EE_SER-AEX-B-LT-I-43.asice
     */
    def "asiceInvalidNonRepudiationKey"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-I-43.asice", SignaturePolicy.POLICY_3.name, "Simple"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureLevel", Matchers.is(SIGNATURE_LEVEL_INDETERMINATE_UNKNOWN))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_CHAIN_CONSTRAINTS_FAILURE))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, NOT_EXPECTED_KEY_USAGE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-7
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice signers certificate does not have non-repudiation value in the certificates key usage field and it does not contain the QC and SSCD compliance information.
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: EE_SER-AEX-B-LT-I-26.asice
     */
    def "asiceInvalidNonRepudiationKeyNoComplianceInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-I-26.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_CHAIN_CONSTRAINTS_FAILURE))
                .body("signatures[0].errors.content", Matchers.contains(
                        CERT_VALIDATION_NOT_CONCLUSIVE,
                        NOT_EXPECTED_KEY_USAGE,
                        CERT_NOT_RELATED_TO_QUALIFIED_TRUST_SERVICE))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-8
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: OCSP certificate is not trusted
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TM-01_bdoc21-unknown-resp.bdoc
     */
    def "asiceNotTrustedOcspCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("TM-01_bdoc21-unknown-resp.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_CERTIFICATE_CHAIN_GENERAL_FAILURE))
                .body("signatures[0].errors.content", Matchers.hasItems(VALID_VALIDATION_PROCESS_ERROR_VALUE_5, REVOCATION_NOT_TRUSTED))
                .body("signatures[0].signedBy", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("SINIVEE,VEIKO,36706020210"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEPzCCAyegAwIBAgIQH0FobucEcidPGVN0HUUgATANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("DemoCA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIDmjCCAoKgAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwgZkxCz"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-9
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice TSA certificate is not trusted
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TS-05_23634_TS_unknown_TSA.asice
     */
    def "asiceNotTrustedTsaCert"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-05_23634_TS_unknown_TSA.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItems(TS_NOT_TRUSTED))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("Time Stamp Authority Server"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIG2jCCBMKgAwIBAgIBCDANBgkqhkiG9w0BAQUFADCBpDELMA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-10
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice OCSP response status is revoked
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: EE_SER-AEX-B-LT-R-25.asice
     */
    def "asiceTsOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-R-25.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_REVOKED_NO_POE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-11-07T11:43:06Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(PAST_SIG_VALIDATION_NOT_CONCLUSIVE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-11
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice difference between OCSP and time-stamp issuing times is more than 24 hours
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: EE_SER-AEX-B-LT-V-20.asice
     */
    def "asiceOcspAndTsDifferenceOver24H"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-20.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-11-07T13:18:01Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(REVOCATION_NOT_FRESH))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-12
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice unsigned data files in the container
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: EE_SER-AEX-B-LT-V-34.asice
     */
    def "asiceUnsignedDataFiles"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-34.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].warnings.content", Matchers.hasItems(VALID_VALIDATION_PROCESS_VALUE_35))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-13
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice SignatureValue does not correspond to the SignedInfo block
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: REF-19_bdoc21-no-sig-asn1-pref.bdoc
     */
    def "asiceSignatureValueDoNotCorrespondToSignedInfo"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("REF-19_bdoc21-no-sig-asn1-pref.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-14
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice Baseline-BES file
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: signWithIdCard_d4j_1.0.4_BES.asice
     */
    def "asiceBaselineBesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("signWithIdCard_d4j_1.0.4_BES.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_B))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, SIG_UNEXPECTED_FORMAT))
                .body("signatures[0].signedBy", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.size()", Matchers.is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEojCCA4qgAwIBAgIQPKphkF8jscxRrFRhBsxlhjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
    }

    /**
     * TestCaseID: Asice-ValidationFail-15
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice Baseline-EPES file
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TM-04_kehtivuskinnituset.4.asice
     */
    def "asiceBaselineEpesSignatureLevel"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-04_kehtivuskinnituset.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_B))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].errors.content", Matchers.hasItems(SIG_UNEXPECTED_FORMAT))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.size()", Matchers.is(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIE/TCCA+WgAwIBAgIQJw9uhQnKff9RdnVKwzk1OzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-16
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice signers certificate is not trusted
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: SS-4_teadmataCA.4.asice
     */
    def "asiceSignersCertNotTrusted"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("SS-4_teadmataCA.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItems(SIG_NOT_TRUSTED, CERT_PATH_NOT_TRUSTED))
                .body("signatures[0].signedBy", Matchers.is("signer1"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("signer1"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIICHDCCAYWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("libdigidocpp Inter"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIICCTCCAXKgAwIBAgIBAzANBgkqhkiG9w0BAQUFADAnMQswCQ"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-17
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice OCSP response status is revoked
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TM-15_revoked.4.asice
     */
    def "asiceTmOcspStatusRevoked"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-15_revoked.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_REVOKED_NO_POE))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2013-10-11T11:27:19Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(PAST_SIG_VALIDATION_NOT_CONCLUSIVE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-18
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice OCSP response status is unknown
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TM-16_unknown.4.asice
     */
    def "asiceTmOcspStatusUnknown"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TM-16_unknown.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItems(REVOCATION_UNKNOWN))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-19
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice signed data file has been removed from the container
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: KS-21_fileeemaldatud.4.asice
     */
    def "asiceSignedFileRemoved"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("KS-21_fileeemaldatud.4.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_SIGNED_DATA_NOT_FOUND))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_FOUND))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-20
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice no files in container
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: KS-02_tyhi.bdoc
     */
    def "asiceNoFilesInContainer"() {
        expect:
        SivaRequests.tryValidate(RequestData.validationRequestForDDS("KS-02_tyhi.bdoc", null, null))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors", Matchers.hasSize(2))
    }

    /**
     * TestCaseID: Asice-ValidationFail-21
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice signed data file(s) don't match the hash values in reference elements
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: REF-14_filesisumuudetud.4.bdoc
     */
    def "asiceDataFilesDontMatchHash"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("REF-14_filesisumuudetud.4.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_HASH_FAILURE))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REFERENCE_DATA_NOT_INTACT))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-22
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice Baseline-T signature
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TS-06_23634_TS_missing_OCSP.asice
     */
    def "asiceBaselineTSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-06_23634_TS_missing_OCSP.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_T))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItems(CERT_VALIDATION_NOT_CONCLUSIVE, REVOCATION_NOT_FOUND))
                .body("signatures[0].signedBy", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEjzCCA3egAwIBAgIQZTNeodpzkAxPgpfyQEp1dTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("TEST of ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIEuzCCA6OgAwIBAgIQSxRID7FoIaNNdNhBeucLvDANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("tsa01.quovadisglobal.com"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIGOzCCBSOgAwIBAgIUe6m/OP/GwmsrkHR8Mz8LJoNedfgwDQ"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-23
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice certificate's validity time is not in the period of OCSP producedAt time
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File:
     */
    @Ignore("Missing test file")
    //TODO: test file is needed where certificate expiration end is before the OCSP produced at time
    def "asiceCertificateValidityOutOfOcspRange"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDDS("", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].errors.content", Matchers.hasItem(SIG_CREATED_WITH_EXP_CERT))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-24
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: BDoc with invalid signature, no signing certificate found
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: TM-invalid-sig-no-sign-cert.asice
     */
    def "asiceInvalidSignatureNoSigningCertificateFound"() {
        expect:
        String fileName = "TM-invalid-sig-no-sign-cert.asice"
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signedBy", Matchers.emptyOrNullString())
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_T))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_NO_SIGNING_CERTIFICATE_FOUND))
                .body("signatures[0].claimedSigningTime", Matchers.is("2013-10-11T11:47:40Z"))
                .body("signatures[0].errors.content", Matchers.hasItems(VALID_VALIDATION_PROCESS_ERROR_VALUE_9, SIG_NO_CANDIDATE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
                .body("validatedDocument.filename", Matchers.is(fileName))
    }

    /**
     * TestCaseID: Asice-ValidationFail-25
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: BDoc with invalid signature, signed with expired certificate
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: IB-5987_signed_with_expired_certificate.asice
     */
    def "asiceSignedWithExpiredCertificate"() {
        expect:
        String fileName = "IB-5987_signed_with_expired_certificate.asice"
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_B))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].claimedSigningTime", Matchers.is("2016-08-01T13:07:13Z"))
                .body("signatures[0].errors.content", Matchers.hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_10))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))
                .body("validatedDocument.filename", Matchers.is(fileName))
    }

    /**
     * TestCaseID: Asice-ValidationFail-26
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Bdoc signed properties element missing
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: REF-03_bdoc21-TS-no-signedpropref.asice
     */
    def "bdocTimemarkSignedPropertiesMissing"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("REF-03_bdoc21-TS-no-signedpropref.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_LT"))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].errors.content", Matchers.hasItem(SIG_QUALIFYING_PROPERTY_MISSING))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-27
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice LT signature signed with expired AIA OCSP certificate
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: esteid2018signerAiaOcspLT.asice
     */
    def "asiceLtSignatureSignedWithExpiredAiaOCSP"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("esteid2018signerAiaOcspLT.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_5))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-28
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice LTA signature signed with expired AIA OCSP certificate
     * <p>
     * Expected Result: The document should fail the validation
     * <p>
     * File: esteid2018signerAiaOcspLTA.asice
     */
    def "asiceLtaSignatureSignedWithExpiredAiaOCSP"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("esteid2018signerAiaOcspLTA.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LTA))
                .body("signatures[0].indication", Matchers.is(INDETERMINATE))
                .body("signatures[0].errors.content", Matchers.hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_5))
                .body("validSignaturesCount", Matchers.is(0))
    }

    /**
     * TestCaseID: Asice-ValidationFail-29
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     *
     * Title: Asice simple/batchsignature/attachment xroad document
     *
     * Expected Result: Document should fail as xroad document validation is not supported
     *
     * File: xroad-simple.asice, xroad-batchsignature.asice, xroad-attachment.asice
     */
    def "asiceSimpleXroadDocumentShouldFail"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(filename, SignaturePolicy.POLICY_3.name))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].signatureFormat", Matchers.is("XML_NOT_ETSI"))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].subIndication", Matchers.is(SUB_INDICATION_FORMAT_FAILURE))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("70006317"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("Riigi Infosüsteemi Amet"))
                .body("signatures[0].errors.content", Matchers.hasItems(SIG_UNEXPECTED_FORMAT))
                .body("validSignaturesCount", Matchers.is(0))
                .body("signaturesCount", Matchers.is(1))

        where:
        filename                     | _
        "xroad-simple.asice"         | _
        "xroad-batchsignature.asice" | _
        "xroad-attachment.asice"     | _
    }

    /**
     * TestCaseID: Asice-ValidationFail-30
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice Baseline-LTA file
     *
     * Expected Result: The document should fail the validation as TS is not qualified
     *
     * File: EE_SER-AEX-B-LTA-V-24.asice
     */
    def "asiceBaselineLtaProfileInvalidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LTA-V-24.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LTA))
                .body("signatures[0].indication", Matchers.is(TOTAL_FAILED))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2014-10-30T18:50:35Z"))
                .body("signatures[0].signedBy", Matchers.is("METSMA,RAUL,38207162766"))
                .body("signatures[0].errors.content", Matchers.contains(VALID_VALIDATION_PROCESS_ERROR_VALUE_11, VALID_VALIDATION_PROCESS_ERROR_VALUE_11))
                .body("signatures[0].certificates.size()", Matchers.is(4))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("METSMA,RAUL,38207162766"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEmzCCA4OgAwIBAgIQFQe7NKtE06tRSY1vHfPijjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("BalTstamp QTSA TSU2"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEtzCCA5+gAwIBAgIKFg5NNQAAAAADhzANBgkqhkiG9w0BAQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].issuer.commonName", Matchers.startsWith("SSC Qualified Class 3 CA"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].issuer.content", Matchers.startsWith("MIIFvTCCA6WgAwIBAgIQWJFmnMAIyiVAcLMn/5wGnjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].commonName", Matchers.is("BalTstamp QTSA TSU2"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEtzCCA5+gAwIBAgIKFg5NNQAAAAADhzANBgkqhkiG9w0BAQ"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].issuer.commonName", Matchers.startsWith("SSC Qualified Class 3 CA"))
                .body("signatures[0].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].issuer.content", Matchers.startsWith("MIIFvTCCA6WgAwIBAgIQWJFmnMAIyiVAcLMn/5wGnjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(0))
    }
}
