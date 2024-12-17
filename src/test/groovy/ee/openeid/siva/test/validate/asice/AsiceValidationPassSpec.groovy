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
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.model.SignatureLevel
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.qameta.allure.Story
import org.hamcrest.Matchers
import org.junit.jupiter.api.Tag

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.equalTo

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy")
class AsiceValidationPassSpec extends GenericSpecification {

    @Description("Asice with single valid signature")
    def "Given ASiC-E with single valid signature, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2024-09-13T14:14:36Z"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].signedBy", Matchers.is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("JÕEORG,JAAK-KRISTJAN,38001085718"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIID6zCCA02gAwIBAgIQT7j6zk6pmVRcyspLo5SqejAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("TEST of ESTEID2018"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFfDCCBN2gAwIBAgIQNhjzSfd2UEpbkO14EY4ORTAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("DEMO SK TIMESTAMPING AUTHORITY 2023E"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIDEjCCApigAwIBAgIQM7BQCImkdt18qWDYdbfOtjAKBggqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("DEMO of ESTEID-SK 2018 AIA OCSP RESPONDER 2018"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIDvTCCAx+gAwIBAgIQeu2FGJib4Jxb4bucEBkycDAKBggqhk"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Asice files with signature from test certificate chain")
    def "Given ASiC-E with signature from #CN certificate chain, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(testFile))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))

                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.is(CN))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith(cert))

        where:
        CN                       | testFile                                   | cert
        // TODO: missing test files
//        "TEST of ESTEID-SK 2007" | ""                         | ""
//        "TEST of ESTEID-SK 2011" | ""                         | ""
        "TEST of ESTEID-SK 2015" | "TEST_ESTEID-SK2015_ASiC-E_XAdES_LT.asice" | "MIIGgzCCBWugAwIBAgIQEDb9gCZi4PdWc7IoNVIbsTANBgkqhk"
        "TEST of ESTEID2018"     | "TEST_ESTEID2018_ASiC-E_XAdES_LT.sce"      | "MIIFfDCCBN2gAwIBAgIQNhjzSfd2UEpbkO14EY4ORTAKBggqhk"

//        "TEST of EID-SK 2016"    | ""                                         | ""

    }

    @Tag("LiveData")
    @Description("Asice files with signature from live certificate chain")
    def "Given ASiC-E with signature from live #CN certificate chain, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(testFile))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))

                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith(CN))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith(cert))

        where:
        CN               | testFile                                                  | cert
        // TODO: missing test files
//        "ESTEID-SK 2007" | ""                                                        | ""
        "ESTEID-SK 2011" | "EE_SER-AEX-B-LT-V-49.asice"                              | "MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"
        "ESTEID-SK 2015" | "IB-4270_TS_ESTEID-SK 2015  SK OCSP RESPONDER 2011.asice" | "MIIGcDCCBVigAwIBAgIQRUgJC4ec7yFWcqzT3mwbWzANBgkqhk"
//        "ESTEID2018"     | ""                                                        | ""

//        "EID-SK 2007"     | ""                                                        | ""
//        "EID-SK 2011"     | ""                                                        | ""
//        TODO: Test file has additional warning:
//          The private key does not reside in a QSCD at (best) signing time!
//          The private key does not reside in a QSCD at issuance time!
//          The signature is not in the Qualified Electronic Signature level
//        "EID-SK 2016"    | "testAdesQC.asice"                                        | "MIIG4jCCBcqgAwIBAgIQO4A6a2nBKoxXxVAFMRvE2jANBgkqhk"
    }

    @Tag("LiveData")
    @Description("Asice files with MID signature from live ESTEID-SK 2015 certificate chain (ECC)")
    def "Given ASiC-E with MID signature from live ESTEID-SK 2015 certificate chain, then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidLiveSignature.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-10-11T09:36:10Z"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIE3DCCAsSgAwIBAgIQSsqdjzAQgvpX80krgJy83DANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("ESTEID-SK 2015"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIGcDCCBVigAwIBAgIQRUgJC4ec7yFWcqzT3mwbWzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Asice with multiple valid signatures")
    def "Given ASiC-E with multiple signatures (#comment), then successful validation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(filename))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationWarnings", Matchers.hasSize(1))
                .body("validationWarnings.content", Matchers.hasItem(TEST_ENV_VALIDATION_WARNING))
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(signatureProfiles[0]))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[1].signatureFormat", Matchers.is(signatureProfiles[1]))
                .body("signatures[1].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].warnings", Matchers.emptyOrNullString())
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signaturesCount", Matchers.is(2))
                .body("validSignaturesCount", Matchers.is(2))

        where:
        comment   | filename                                   | signatureProfiles
        "TM+LT"   | "TEST_ASiC-E_XAdES_TM+LT.asice"            | [SignatureFormat.XAdES_BASELINE_LT_TM, SignatureFormat.XAdES_BASELINE_LT]
        "LT+LT"   | "TEST_ESTEID2018_ASiC-E_XAdES_LT+LT.sce"   | [SignatureFormat.XAdES_BASELINE_LT, SignatureFormat.XAdES_BASELINE_LT]
        "LT+LTA"  | "TEST_ESTEID2018_ASiC-E_XAdES_LT+LTA.sce"  | [SignatureFormat.XAdES_BASELINE_LT, SignatureFormat.XAdES_BASELINE_LTA]
        "LTA+LTA" | "TEST_ESTEID2018_ASiC-E_XAdES_LTA+LTA.sce" | [SignatureFormat.XAdES_BASELINE_LTA, SignatureFormat.XAdES_BASELINE_LTA]

    }

    @Description("Asice One LT signature with certificates from different countries")
    def "asiceDifferentCertificateCountries"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-30.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("PELANIS,MINDAUGAS,37412260478"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MINDAUGAS PELANIS"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("37412260478"))
                .body("signatures[0].subjectDistinguishedName.givenName", Matchers.is("MINDAUGAS"))
                .body("signatures[0].subjectDistinguishedName.surname", Matchers.is("PELANIS"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("MINDAUGAS PELANIS"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIGJzCCBQ+gAwIBAgIObV8h37aTlaYAAQAEAckwDQYJKoZIhv"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("VI Registru Centras RCSC (IssuingCA-A)"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIF7jCCBNagAwIBAgIOEvrAfT5Zs1YAAwAAABkwDQYJKoZIhv"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Asice Baseline-LT file")
    def "asiceBaselineLtProfileValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-49.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-05-23T10:06:23Z"))
                .body("signatures[0].signedBy", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("UUKKIVI,KRISTI,48505280278"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEojCCA4qgAwIBAgIQPKphkF8jscxRrFRhBsxlhjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("ESTEID-SK 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIFBTCCA+2gAwIBAgIQKVKTqv2MxtRNgzCjwmRRDTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Asice file signed with Mobile-ID, ECC-SHA256 signature with prime256v1 key")
    def "asiceWithEccSha256ValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-2.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("Asice file with KLASS3-SK 2010 (EECCRCA) certificate chain")
    def "asiceKlass3Sk2010CertificateChainValidSignature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("EE_SER-AEX-B-LT-V-28.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("Wilson OÜ digital stamp"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("Wilson OÜ digital stamp"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("12508548"))
                .body("signatures[0].subjectDistinguishedName.givenName", Matchers.emptyOrNullString())
                .body("signatures[0].subjectDistinguishedName.surname", Matchers.emptyOrNullString())
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("Wilson OÜ digital stamp"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIEcDCCA1igAwIBAgIQBCCW1H7A4/xUfYW+dTWZgzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.commonName", Matchers.startsWith("KLASS3-SK 2010"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].issuer.content", Matchers.startsWith("MIIErDCCA5SgAwIBAgIQAznVp1LayatNgy6bN8f9QjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("KLASS3-SK 2010 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIELzCCAxegAwIBAgICAMswDQYJKoZIhvcNAQEFBQAwbTELMA"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].issuer.commonName", Matchers.startsWith("KLASS3-SK 2010"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].issuer.content", Matchers.startsWith("MIIErDCCA5SgAwIBAgIQAznVp1LayatNgy6bN8f9QjANBgkqhk"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("*.sce file with TimeStamp")
    def "asiceWithSceFileExtensionShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3_signatures_TM_LT_LTA.sce"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("signatures[2].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LTA))
                .body("signatures[2].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[2].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[2].info.bestSignatureTime", Matchers.is("2021-01-29T14:38:11Z"))
                .body("signatures[2].subjectDistinguishedName.commonName", Matchers.notNullValue())
                .body("signatures[2].subjectDistinguishedName.serialNumber", Matchers.notNullValue())
                .body("signatures[2].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].commonName", Matchers.is("DEMO SK TIMESTAMPING AUTHORITY 2020"))
                .body("signatures[2].certificates.findAll{it.type == 'ARCHIVE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEgzCCA2ugAwIBAgIQcGzJsYR4QLlft+S73s/WfTANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(3))
                .body("signaturesCount", Matchers.is(3))
    }

    @Description("Asice-TS with special characters in data file")
    def "asiceWithSpecialCharactersInDataFileShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Nonconventionalcharacters.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", Matchers.is(SignatureLevel.QESIG))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureScopes[0].name", Matchers.is("!~#¤%%&()=+-_.txt"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is(SIGNATURE_SCOPE_FULL))
                .body("signatures[0].signatureScopes[0].content", Matchers.is(VALID_SIGNATURE_SCOPE_CONTENT_FULL))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1))
    }

    @Description("New Estonian ECC signature")
    def "asiceEccSignatureShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("47101010033"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))

    }

    @Description("Asice pss signature")
    def "asicePssSignatureShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("PSS-signature.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("signatures[0].signatureMethod", Matchers.is("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"))
                .body("signatures[0].signedBy", Matchers.is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("11404176865"))
                .body("validationLevel", Matchers.is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", Matchers.is(1))

    }

    @Description("Asice with empty datafiles")
    def "asiceWithEmptyDataFilesShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("signed-container-with-empty-datafiles.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureScopes.size()", Matchers.is(5))
                .body("signatures[0].signatureScopes.name", Matchers.containsInRelativeOrder(
                        "data-file-1.txt", "empty-file-2.txt", "data-file-3.txt", "empty-file-4.txt", "data-file-5.txt"
                ))
                .body("signatures[0].warnings.size()", Matchers.is(2))
                .body("signatures[0].warnings.content", Matchers.containsInAnyOrder(
                        "Data file 'empty-file-2.txt' is empty",
                        "Data file 'empty-file-4.txt' is empty"
                ))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1))
    }

    @Description("ASICE with new Smart-ID certificate profile without personal number in CommonName")
    def "validSignatureSignerCertDoNotHavePersonalNumberInCnShouldPass"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validSidSignatureWithCertWithoutPnoInCn.asice"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(ContainerFormat.ASiC_E))
                .body("signatures[0].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("TESTNUMBER,QUALIFIED OK1,30303039914"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("TESTNUMBER,QUALIFIED OK1"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("PNOEE-30303039914"))
                .body("signatures[1].signatureFormat", Matchers.is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[1].indication", Matchers.is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].signedBy", Matchers.is("TESTNUMBER,BOD,39912319997"))
                .body("signatures[1].subjectDistinguishedName.commonName", Matchers.is("TESTNUMBER,BOD"))
                .body("signatures[1].subjectDistinguishedName.serialNumber", Matchers.is("PNOEE-39912319997"))
                .body("signatures[1].certificates.size()", Matchers.is(3))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNING'}[0].commonName", Matchers.is("TESTNUMBER,BOD"))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNING'}[0].content", Matchers.startsWith("MIIIojCCBoqgAwIBAgIQJ5zu8nauSO5hSFPXGPNAtzANBgkqhk"))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is("DEMO SK TIMESTAMPING AUTHORITY 2020"))
                .body("signatures[1].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content", Matchers.startsWith("MIIEgzCCA2ugAwIBAgIQcGzJsYR4QLlft+S73s/WfTANBgkqhk"))
                .body("signatures[1].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", Matchers.is("DEMO of EID-SK 2016 AIA OCSP RESPONDER 2018"))
                .body("signatures[1].certificates.findAll{it.type == 'REVOCATION'}[0].content", Matchers.startsWith("MIIFQDCCAyigAwIBAgIQSKlAnTgs72Ra5xCvMScb/jANBgkqhk"))
                .body("signaturesCount", Matchers.is(2))
                .body("validSignaturesCount", Matchers.is(2))
    }

    @Story("Only QTST timestamp allowed")
    @Description("Asice LT signature passes without warnings/errors, when timestamp level was during signing QTST")
    def "Asice LT signature with QTST timestamp passes: #description"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(testfile))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", equalTo(1))
                .body("signaturesCount", equalTo(1))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName", Matchers.is(timestamp))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[0].errors", emptyOrNullString())

        where:
        description                                          | testfile                       | timestamp
        "QTST level present in TSL before eIDAS"             | "singleValidSignatureTS.asice" | "DEMO of SK TSA 2014"
        "QTST level, but withdrawn during validation in TSL" | "EE_SER-AEX-B-LT-V-30.asice"   | "SK TIMESTAMPING AUTHORITY"
//TODO: SIVA-796 "QTST level during signing, before was non-qualified in TSL" | "< testfile needed >"          | ""
    }
}
