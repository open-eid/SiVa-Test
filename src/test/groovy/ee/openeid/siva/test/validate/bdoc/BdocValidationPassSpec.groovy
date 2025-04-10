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

package ee.openeid.siva.test.validate.bdoc

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.TestData
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import spock.lang.Ignore

import static org.hamcrest.Matchers.*

class BdocValidationPassSpec extends GenericSpecification {

    @Description("All signature profiles in container are validated")
    def "Given validation request with BDOC #profile signature, then validation report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("validatedDocument.filename", equalTo(file))
                .body("signatures[0].signatureFormat", is(profile))

        where:
        profile                               | file
        SignatureFormat.XAdES_BASELINE_LT_TM  | "TEST_ESTEID2018_ASiC-E_XAdES_TM_OCSP2011.bdoc"
        SignatureFormat.XAdES_BASELINE_B_BES  | "TEST_ESTEID2018_ASiC-E_XAdES_B_BES.bdoc"
        SignatureFormat.XAdES_BASELINE_B_EPES | "TEST_ESTEID2018_ASiC-E_XAdES_B_EPES.bdoc"
    }

    @Description("Bdoc with single valid signature")
    def "Given BDOC with single valid signature, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_TM_OCSP2011.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID6zCCA02gAwIBAgIQT7j6zk6pmVRcyspLo5SqejAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhk"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc TM with multiple valid signatures")
    def "Given BDOC with multiple TM signatures, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TwoValidTmSignaturesWithRolesAndProductionPlace.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    @Ignore
    //TODO: New file needed. This one has different mimetype value in manifest.xml and signature.xml
    @Description("Bdoc with warning on signature")
    def "alidSignatureWithWarning"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("bdoc_weak_warning_sha1.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].subIndication", is(""))
                .body("validSignaturesCount", is(1))

    }

    @Description("Asice One LT signature with certificates from different countries")
    def "bdocDifferentCertificateCountries"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-30.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("PELANIS,MINDAUGAS,37412260478"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MINDAUGAS PELANIS"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("37412260478"))
                .body("signatures[0].certificates.size()", is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("MINDAUGAS PELANIS"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIGJzCCBQ+gAwIBAgIObV8h37aTlaYAAQAEAckwDQYJKoZIhv"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc signed with Mobile-ID, ECC-SHA256 signature with prime256v1 key")
    def "bdocEccSha256signature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("24050_short_ecdsa_correct_file_mimetype.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Asice Baseline-LT file")
    def "bdocBaselineLtProfileValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-49.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
    }

    @Description("Asice QES file")
    def "bdocQESProfileValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("ValidLiveSignature.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2016-10-11T09:36:10Z"))
                .body("validSignaturesCount", is(1))
    }

    @Description("Asice file signed with Mobile-ID, ECC-SHA256 signature with prime256v1 key")
    def "bdocWithEccSha256ValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-2.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
    }

    @Description("Asice file with \tESTEID-SK 2015 certificate chain")
    def "bdocSk2015CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("IB-4270_TS_ESTEID-SK 2015  SK OCSP RESPONDER 2011.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
    }

    @Description("Asice file with KLASS3-SK 2010 (EECCRCA) certificate chain")
    def "bdocKlass3Sk2010CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("EE_SER-AEX-B-LT-V-28.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("Wilson OÜ digital stamp"))
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc with Baseline-LT_TM and QES signature level and ESTEID-SK 2011 certificate chain with valid signature")
    def "bdocEsteidSk2011CertificateChainQesBaselineLtTmValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("BDOC2.1.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc TS with multiple valid signatures")
    def "bdocTsValidMultipleSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("Test_id_aa.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(2))
    }

    @Description("Bdoc-TM with special characters in data file")
    def "bdocWithSpecialCharactersInDataFileShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Šužlikud sõid ühe õuna ära.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("*.sce file with TimeMark")
    def "bdocWithSceFileExtensionShouldPass"() {
        expect:

        SivaRequests.validate(RequestData.validationRequestForDD4J("BDOC2.1_content_as_sce.sce", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2013-11-25T13:16:59Z"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Bdoc-TS with special characters in data file")
    def "asiceWithSpecialCharactersInDataFileShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("Nonconventionalcharacters.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureScopes[0].name", is("!~#¤%%&()=+-_.txt"))
                .body("signatures[0].signatureScopes[0].scope", is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", is("Digest of the document content"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("ECC signature vith BDOC TM")
    def "bdocWithEccTimeMarkShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("testECCDemo.bdoc", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("ECC signature vith BDOC TS")
    def "bdocWithEccTimeStampShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequestForDD4J("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice", null, null))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Description("Asice with wrong slash character ('\\') in data file mime-type value")
    def "bdocInvalidMimeTypeCharsShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-33.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2016-04-13T08:37:52Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc with invalid mimetype in manifest")
    def "bdocMalformedBdocWithInvalidMimetypeInManifestShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("23147_weak-warning-sha1-invalid-mimetype-in-manifest.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2013-11-13T10:09:49Z"))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc with TEST of SK OCSP RESPONDER 2020")
    def "validSignatureTestOfOCSPResponder2020ForTimeMarkShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("test_of_OCSP_responder_2020.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.size()", is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIIFvjCCA6agAwIBAgIQN7pWa1fk0oJaAwZD/BO7MjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("TEST of SK OCSP RESPONDER 2020"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIEzjCCA7agAwIBAgIQa7w4iGoiIOtfrn0fG/hc1zANBgkqhk"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Bdoc with empty datafiles")
    def "bdocWithEmptyDataFilesShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("signed-container-with-empty-datafiles.bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureScopes.size()", is(5))
                .body("signatures[0].signatureScopes.name", containsInRelativeOrder(
                        "data-file-1.txt", "empty-file-2.txt", "data-file-3.txt", "empty-file-4.txt", "data-file-5.txt"
                ))
                .body("signatures[0].warnings.size()", is(2))
                .body("signatures[0].warnings.content", containsInAnyOrder(
                        "Data file 'empty-file-2.txt' is empty", "Data file 'empty-file-4.txt' is empty"
                ))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given BDOC with timestamped signature, then validation report includes timestampCreationTime field"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file, "bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[0].info.timestampCreationTime", is(timestampCreationTime))

        where:
        file                                   | timestampCreationTime
        "TEST_ESTEID2018_ASiC-E_XAdES_T.sce"   | "2024-09-13T14:14:24Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"  | "2024-09-13T14:14:36Z"
        "TEST_ESTEID2018_ASiC-E_XAdES_LTA.sce" | "2024-09-13T14:14:47Z"
    }

    @Description("Simple report includes timestamp creation time for timestamped signature")
    def "Given BDOC with multiple timestamped signatures, then validation report includes timestampCreationTime field for each"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.sce", "bdoc"))
                .then().rootPath(TestData.VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("signatures[1].info.timestampCreationTime", is("2021-01-29T14:31:36Z"))
                .body("signatures[2].info.timestampCreationTime", is("2021-01-29T14:38:11Z"))
    }
}
