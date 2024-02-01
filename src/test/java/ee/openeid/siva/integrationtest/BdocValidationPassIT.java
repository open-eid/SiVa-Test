/*
 * Copyright 2017 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
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

package ee.openeid.siva.integrationtest;


import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static ee.openeid.siva.integrationtest.TestData.*;

@Tag("IntegrationTest")
public class BdocValidationPassIT extends SiVaRestTests {
    private static final String DEFAULT_TEST_FILES_DIRECTORY = "bdoc/live/timemark/";
    private String testFilesDirectory = DEFAULT_TEST_FILES_DIRECTORY;

    @BeforeEach
    public void DirectoryBackToDefault() {
        setTestFilesDirectory(DEFAULT_TEST_FILES_DIRECTORY);
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-1
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc with single valid signature
     *
     * Expected Result: The document should pass the validation
     *
     * File: Valid_ID_sig.bdoc
     */
    @Test
    public void validSignature() {
        post(validationRequestFor("Valid_ID_sig.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName",  Matchers.is("NURM,AARE,38211015222"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content",  Matchers.startsWith("MIIEmDCCA4CgAwIBAgIQP0r+1SmYLpVSgfYqBWYcBzANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName",  Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content",  Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-2
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc TM with multiple valid signatures
     *
     * Expected Result: The document should pass the validation
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Test
    public void validMultipleSignatures() {
        post(validationRequestFor("Valid_IDCard_MobID_signatures.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signatures[1].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[1].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(2))
                .body("validSignaturesCount", Matchers.is(2));

    }

    /**
     * TestCaseID: Bdoc-ValidationPass-3
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc with warning on signature
     *
     * Expected Result: The document should pass the validation but warning should be returned
     *
     * File: bdoc_weak_warning_sha1.bdoc
     */
    @Test
    @Disabled //TODO: New file needed. This one has different mimetype value in manifest.xml and signature.xml
    public void validSignatureWithWarning() {
        setTestFilesDirectory("bdoc/live/timemark/");
        post(validationRequestFor("bdoc_weak_warning_sha1.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].subIndication", Matchers.is(""))
                .body("validSignaturesCount", Matchers.is(1));

    }

    /**
     * TestCaseID: Bdoc-ValidationPass-4
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice One LT signature with certificates from different countries
     *
     * Expected Result: The document should pass the validation
     *
     * File: EE_SER-AEX-B-LT-V-30.asice
     */
    @Test
    public void bdocDifferentCertificateCountries() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("EE_SER-AEX-B-LT-V-30.asice",null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].signedBy", Matchers.is("PELANIS,MINDAUGAS,37412260478"))
                .body("signatures[0].subjectDistinguishedName.commonName",  Matchers.is("MINDAUGAS PELANIS"))
                .body("signatures[0].subjectDistinguishedName.serialNumber",  Matchers.is("37412260478"))
                .body("signatures[0].certificates.size()", Matchers.is(3))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName",  Matchers.is("MINDAUGAS PELANIS"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content",  Matchers.startsWith("MIIGJzCCBQ+gAwIBAgIObV8h37aTlaYAAQAEAckwDQYJKoZIhv"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].commonName",  Matchers.is("SK TIMESTAMPING AUTHORITY"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNATURE_TIMESTAMP'}[0].content",  Matchers.startsWith("MIIEDTCCAvWgAwIBAgIQJK/s6xJo0AJUF/eG7W8BWTANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName",  Matchers.is("SK OCSP RESPONDER 2011"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content",  Matchers.startsWith("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhk"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-5
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc signed with Mobile-ID, ECC-SHA256 signature with prime256v1 key
     *
     * Expected Result: The document should pass the validation
     *
     * File: 24050_short_ecdsa_correct_file_mimetype.bdoc
     */
    @Test
    public void bdocEccSha256signature() {
        post(validationRequestFor("24050_short_ecdsa_correct_file_mimetype.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-6
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice Baseline-LT file
     *
     * Expected Result: The document should pass the validation in DD4J
     *
     * File: EE_SER-AEX-B-LT-V-49.asice
     */
    @Test
    public void bdocBaselineLtProfileValidSignature() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("EE_SER-AEX-B-LT-V-49.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-7
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice QES file
     *
     * Expected Result: The document should pass the validation
     *
     * File: ValidLiveSignature.asice
     */
    @Test
    public void bdocQESProfileValidSignature() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("ValidLiveSignature.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-10-11T09:36:10Z"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-9
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice file signed with Mobile-ID, ECC-SHA256 signature with prime256v1 key
     *
     * Expected Result: The document should pass the validation
     *
     * File: EE_SER-AEX-B-LT-V-2.asice
     */
    @Test
    public void bdocWithEccSha256ValidSignature() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("EE_SER-AEX-B-LT-V-2.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-10
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice file with 	ESTEID-SK 2015 certificate chain
     *
     * Expected Result: The document should pass the validation
     *
     * File: IB-4270_TS_ESTEID-SK 2015  SK OCSP RESPONDER 2011.asice
     */
    @Test
    public void bdocSk2015CertificateChainValidSignature() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("IB-4270_TS_ESTEID-SK 2015  SK OCSP RESPONDER 2011.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-11
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Asice file with KLASS3-SK 2010 (EECCRCA) certificate chain
     *
     * Expected Result: The document should pass the validation
     *
     * File: EE_SER-AEX-B-LT-V-28.asice
     */
    @Test
    public void bdocKlass3Sk2010CertificateChainValidSignature() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("EE_SER-AEX-B-LT-V-28.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].signedBy", Matchers.is("Wilson OÜ digital stamp"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-12
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc with Baseline-LT_TM and QES signature level and ESTEID-SK 2011 certificate chain with valid signature
     *
     * Expected Result: The document should pass the validation
     *
     * File: BDOC2.1.bdoc
     */
    @Test
    public void bdocEsteidSk2011CertificateChainQesBaselineLtTmValidSignature() {
        setTestFilesDirectory("bdoc/live/timemark/");
        post(validationRequestFor("BDOC2.1.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-13
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc TS with multiple valid signatures
     *
     * Expected Result: The document should pass the validation
     *
     * File: Test_id_aa.asice
     */
    @Test
    public void bdocTsValidMultipleSignatures() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("Test_id_aa.asice",null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(2));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-14
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4
     *
     * Title: Bdoc-TM with special characters in data file
     *
     * Expected Result: The document should pass the validation
     *
     * File: Šužlikud sõid ühe õuna ära.bdoc
     */
    @Test
    public void bdocWithSpecialCharactersInDataFileShouldPass() {
        setTestFilesDirectory("bdoc/live/timemark/");
        post(validationRequestFor("Šužlikud sõid ühe õuna ära.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-15
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     *
     * Title: *.sce file with TimeMark
     *
     * Expected Result: The document should pass the validation
     *
     * File: BDOC2.1_content_as_sce.sce
     */
    @Test
    public void bdocWithSceFileExtensionShouldPass() {

        setTestFilesDirectory("bdoc/live/timemark/");
        post(validationRequestForDD4j("BDOC2.1_content_as_sce.sce", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2013-11-25T13:16:59Z"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-17
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     *
     * Title: Bdoc-TS with special characters in data file
     *
     * Expected Result: The document should pass the validation with correct signature scope
     *
     * File: Nonconventionalcharacters.asice
     */
    @Test
    public void asiceWithSpecialCharactersInDataFileShouldPass() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestForDD4j("Nonconventionalcharacters.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].name", Matchers.is("!~#¤%%&()=+-_.txt"))
                .body("signatures[0].signatureScopes[0].scope", Matchers.is("FullSignatureScope"))
                .body("signatures[0].signatureScopes[0].content", Matchers.is("Digest of the document content"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-19
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     *
     * Title: ECC signature vith BDOC TM
     *
     * Expected Result: The document should pass the validation
     *
     * File: testECCDemo.bdoc
     */
    @Test
    public void bdocWithEccTimeMarkShouldPass() {
        setTestFilesDirectory("bdoc/test/timemark/");
        post(validationRequestFor("testECCDemo.bdoc", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT_TM"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].signedBy", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", Matchers.is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", Matchers.is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-20
     *
     * TestType: Automated
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     *
     * Title: ECC signature vith BDOC TS
     *
     * Expected Result: The document should pass the validation
     *
     * File: Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice
     */
    @Test
    public void bdocWithEccTimeStampShouldPass() {

        setTestFilesDirectory("bdoc/test/timestamp/");
        post(validationRequestForDD4j("Mac_AS0099904_EsimeneAmetlikSKTestElliptilistega_TS.asice", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].signatureFormat", Matchers.is("XAdES_BASELINE_LT"))
                .body("signatures[0].signatureLevel", Matchers.is("QESIG"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("validSignaturesCount", Matchers.is(1))
                .body("signaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-21
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Asice with wrong slash character ('\') in data file mime-type value
     * <p>
     * Expected Result: The document should pass
     * <p>
     * File: EE_SER-AEX-B-LT-V-33.bdoc
     */
    @Test
    public void bdocInvalidMimeTypeCharsShouldPass() {
        setTestFilesDirectory("bdoc/live/timestamp/");
        post(validationRequestFor("EE_SER-AEX-B-LT-V-33.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2016-04-13T08:37:52Z"))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("validSignaturesCount", Matchers.is(1));
    }


    /**
     * TestCaseID: Bdoc-ValidationPass-22
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Bdoc with invalid mimetype in manifest
     * <p>
     * Expected Result: The document should pass
     * <p>
     * File: 23147_weak-warning-sha1-invalid-mimetype-in-manifest.bdoc
     */
    @Test
    public void bdocMalformedBdocWithInvalidMimetypeInManifestShouldPass() {
        post(validationRequestFor("23147_weak-warning-sha1-invalid-mimetype-in-manifest.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is("ASiC-E"))
                .body("signatures[0].indication", Matchers.is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", Matchers.is("2013-11-13T10:09:49Z"))
                .body("signatures[0].warnings", Matchers.emptyOrNullString())
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-23
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Bdoc with TEST of SK OCSP RESPONDER 2020
     * <p>
     * Expected Result: The document should pass
     * <p>
     * File: test_of_OCSP_responder_2020.bdoc
     */

    @Test
    public void validSignatureTestOfOCSPResponder2020ForTimeMarkShouldPass() {
        setTestFilesDirectory("bdoc/test/timemark/");
        post(validationRequestFor("test_of_OCSP_responder_2020.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signatures[0].signedBy", Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.size()", Matchers.is(2))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName",  Matchers.is("ŽAIKOVSKI,IGOR,37101010021"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content",  Matchers.startsWith("MIIFvjCCA6agAwIBAgIQN7pWa1fk0oJaAwZD/BO7MjANBgkqhk"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName",  Matchers.is("TEST of SK OCSP RESPONDER 2020"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content",  Matchers.startsWith("MIIEzjCCA7agAwIBAgIQa7w4iGoiIOtfrn0fG/hc1zANBgkqhk"))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1));
    }

    /**
     * TestCaseID: Bdoc-ValidationPass-24
     * <p>
     * TestType: Automated
     * <p>
     * Requirement: http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4
     * <p>
     * Title: Bdoc with empty datafiles
     * <p>
     * Expected Result: The document should pass the validation but with warnings about empty datafiles
     * <p>
     * File: signed-container-with-empty-datafiles.bdoc
     */
    @Test
    public void bdocWithEmptyDataFilesShouldPass() {
        setTestFilesDirectory("bdoc/test/timemark/");
        post(validationRequestFor("signed-container-with-empty-datafiles.bdoc"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", Matchers.is(SIGNATURE_FORM_ASICE))
                .body("signatures[0].signatureFormat", Matchers.is(SIGNATURE_FORMAT_XADES_LT_TM))
                .body("signatures[0].indication", Matchers.is(TOTAL_PASSED))
                .body("signatures[0].signatureScopes.size()", Matchers.is(5))
                .body("signatures[0].signatureScopes.name", Matchers.containsInRelativeOrder(
                        "data-file-1.txt", "empty-file-2.txt", "data-file-3.txt", "empty-file-4.txt", "data-file-5.txt"
                ))
                .body("signatures[0].warnings.size()", Matchers.is(2))
                .body("signatures[0].warnings.content", Matchers.containsInAnyOrder(
                        "Data file 'empty-file-2.txt' is empty", "Data file 'empty-file-4.txt' is empty"
                ))
                .body("signaturesCount", Matchers.is(1))
                .body("validSignaturesCount", Matchers.is(1));
    }

    @Override
    protected String getTestFilesDirectory() {
        return testFilesDirectory;
    }

    public void setTestFilesDirectory(String testFilesDirectory) {
        this.testFilesDirectory = testFilesDirectory;
    }
}
