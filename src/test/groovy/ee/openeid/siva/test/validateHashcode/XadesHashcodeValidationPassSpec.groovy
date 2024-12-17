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

package ee.openeid.siva.test.validateHashcode

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.HashAlgo
import ee.openeid.siva.test.model.ReportType
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static ee.openeid.siva.test.TestData.VALIDATION_LEVEL_ARCHIVAL_DATA
import static org.hamcrest.Matchers.emptyOrNullString
import static org.hamcrest.Matchers.is

@Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
class XadesHashcodeValidationPassSpec extends GenericSpecification {

    @Description("Validation of xades acceptance")
    def "xadesDocumentShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("signatures0.xml", SignaturePolicy.POLICY_4, ReportType.SIMPLE))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    @Description("XAdES extracted from ASICE")
    def "validXadesWithHashcodeFromAsice() throws IOException, SAXException, ParserConfigurationException"() {
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS.xml", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:27:24Z"))
    }

    @Description("XAdES extracted from BDOC")
    def "validXadesWithHashcodeFromBdoc"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TM.xml", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:36:23Z"))
    }

    @Description("XAdES extracted from BDOC")
    def "validXadesWithHashcodeWithMultipleDataFiles"() {
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS_multiple_datafiles.xml", null, null))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T12:48:26Z"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile has + in name")
    def "validXadesWithPlusInDataFileName"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("test+document.xml", null, null, "test+document.txt", HashAlgo.SHA256, "heKN3NGQ0HttzgmfKG0L243dfG7W+6kTMO5n7YbKeS4="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T12:43:15Z"))
                .body("signatures[0].signatureScopes[0].name", is("test+document.txt"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile has space in name")
    def "validXadesWithSpaceInDataFileName"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("spacesInDatafile.xml", null, null, "Te st in g.txt", HashAlgo.SHA256, "5UxI8Rm1jUZm48+Vkdutyrsyr3L/MPu/RK1V81AeKEY="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:22:04Z"))
                .body("signatures[0].signatureScopes[0].name", is("Te st in g.txt"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile digest in SHA1")
    def "sha1DatafileDigestSignatureShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("sha1_TM.xml", null, null, "test.txt", HashAlgo.SHA1, "qP3CBanxnMHHUHpgxPAbE9Edf9A="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA1))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile digest in SHA224")
    def "sha224DatafileDigestSignatureShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("sha224_TS.xml", null, null, "test1.txt", HashAlgo.SHA224, "C7YzVACWz0f8pxd7shHKB1BzOuIuSjBysO3xgw=="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA224))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile digest in SHA256")
    def "sha256DatafileDigestSignatureShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS.xml", null, null, "test.txt", HashAlgo.SHA256, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile digest in SHA384")
    def "sha384DatafileDigestSignatureShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("sha384_TS.xml", null, null, "test1.txt", HashAlgo.SHA384, "DU5PS1Qcd2gu8U3g+4hDYldhAoT/sxEWz6YV8cEdjAaVEFMYSNOypSL+xt4KkK9k"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA384))
                .body("validSignaturesCount", is(1))
    }

    @Description("Datafile digest in SHA512")
    def "sha512DatafileDigestSignatureShouldPass"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("sha512_TS.xml", null, null, "test1.txt", HashAlgo.SHA512, "pA2Dh2/WoCnnxGL9PZd+DQivXUmq8dQG1nyQY3phKZPKlm/HfZZDG8yB79hTG2F4pV9LqW+6SGsETE9d+LQsRg=="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is("TOTAL-PASSED"))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA512))
                .body("validSignaturesCount", is(1))
    }
}
