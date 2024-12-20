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
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.is

class XadesHashcodeValidationFailSpec extends GenericSpecification {

    @Description("Data file hash algorithm do not match signature hash algorithm")
    @Link("http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4")
    def "dataFileHashAlgorithmDoesNotMatchWithSignatureDataFileHashAlgorithm"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TM.xml", null, null, "test.txt", HashAlgo.SHA512, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", hasItem(REFERENCE_DATA_NOT_FOUND))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:36:23Z"))
                .body("signatures[0].signedBy", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Hashes do not match")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
    def "dataFileHashDoesNotMatchWithSignatureFile"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TM.xml", null, null, "test.txt", HashAlgo.SHA256, "kl2ZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("HASH_FAILURE"))
                .body("signatures[0].errors.content", hasItem(REFERENCE_DATA_NOT_INTACT))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:36:23Z"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Wrong data file name is used")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
    def "dataFileFilenameDoesNotMatchWithSignatureFile"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS.xml", null, null, "wrongDataFileName.jpg", HashAlgo.SHA256, "Sj/WcgsM57hpCiR5E8OycJ4jioYwdHzz3s4e5LXditA="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].indication", is(SignatureIndication.INDETERMINATE))
                .body("signatures[0].subIndication", is("SIGNED_DATA_NOT_FOUND"))
                .body("signatures[0].errors.content", hasItem(REFERENCE_DATA_NOT_FOUND))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:27:24Z"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("47101010033"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("MÄNNIK,MARI-LIIS,47101010033"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Invalid signature in XAdES")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
    def "invalidSignature"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Invalid_XAdES_LT_TM.xml", null, null, "test.txt", HashAlgo.SHA256, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:36:23Z"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }

    @Description("Invalid signature in XAdES")
    @Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
    def "invalidBase64Signature"() {
        expect:
        SivaRequests.validateHashcode(RequestData.hashcodeValidationRequest("Invalid_base64_XAdES_LT_TM.xml", null, null, "test.txt", HashAlgo.SHA256, "RnKZobNWVy8u92sDL4S2j1BUzMT5qTgt6hm90TfAGRo="))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].indication", is("TOTAL-FAILED"))
                .body("signatures[0].subIndication", is("SIG_CRYPTO_FAILURE"))
                .body("signatures[0].errors.content", hasItem(VALID_VALIDATION_PROCESS_ERROR_VALUE_9))
                .body("signatures[0].info.bestSignatureTime", is("2019-02-05T13:36:23Z"))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))
                .body("validSignaturesCount", is(0))
    }
}
