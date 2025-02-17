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

package ee.openeid.siva.test

import ee.openeid.siva.test.model.RequestError
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestErrorValidator
import io.qameta.allure.Description
import io.restassured.response.Response
import org.apache.http.HttpStatus
import spock.lang.Ignore
import spock.lang.Tag

@Ignore("Rewrite these tests in siga-log-test to check logs from elk automatically")
@Tag("ManualTest")
class StatisticsToLogsSpec extends GenericSpecification {
    /*
    * Note: All tests in this class expect manual verification of responses in log! The tests are made to prepare test data and ease the test execution.
    */

    /**
     * TestCaseID: Bdoc-Statistics-Log-1
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Bdoc valid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: Valid_IDCard_MobID_signatures.bdoc
     */
    @Description("")
    def "bdocWithValidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("Valid_IDCard_MobID_signatures.bdoc", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "ASiC-E",
          "usrId" : "XAuthTest",
          "dur": 68, <- Can vary, verify that its present
          "sigCt": 2,
          "vSigCt": 2,
          "sigRslt": [
             {"i":"TOTAL-PASSED", "cc":"EE", "sf" : "XAdES_BASELINE_LT_TM"},
             {"i":"TOTAL-PASSED", "cc":"EE", "sf" : "XAdES_BASELINE_LT_TM"}
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Bdoc-Statistics-Log-2
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Bdoc invalid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: SS-4_teadmataCA.4.asice
     */
    @Description("")
    def "bdocWithInvalidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("SS-4_teadmataCA.4.asice", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "ASiC-E",
          "usrId" : "XAuthTest",
          "dur": 585, <- Can vary, verify that its present
          "sigCt": 1,
          "vSigCt": 0,
          "sigRslt": [
             {"i":"TOTAL-FAILED", "si":"FORMAT_FAILURE", "cc":"EE", "sf" : "XAdES_BASELINE_T"}
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Bdoc-Statistics-Log-3
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Bdoc not supported file is inserted
     *
     * Expected Result: No message in statistics as the container is not validated
     *
     * File: xroad-simple.asice
     */
    @Ignore("SIVA-352 - remark 8")
    @Description("")
    def "bdocWithErrorResponse"() {
        when:
        Response response = SivaRequests.validate(RequestData.validationRequest("xroad-simple.bdoc", SignaturePolicy.POLICY_3))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    /**
     * TestCaseID: Bdoc-Statistics-Log-4
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Bdoc with certificates from different countries.
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: Baltic MoU digital signing_EST_LT_LV.bdoc
     */
    @Description("")
    def "bdocWithSignaturesFromDifferentCountries"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("Baltic MoU digital signing_EST_LT_LV.bdoc", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "ASiC-E",
          "usrId" : "XAuthTest",
          "dur": 1334, <- Can vary, verify that its present
          "sigCt": 3,
          "vSigCt": 3,
          "sigRslt": [
             {"i":"TOTAL-PASSED", "cc":"EE", "sf" : "XAdES_BASELINE_LT_TM"},
             {"i":"TOTAL-PASSED", "cc":"LT", "sf" : "XAdES_BASELINE_LT_TM"},
             {"i":"TOTAL-PASSED", "cc":"LV", "sf" : "XAdES_BASELINE_LT_TM"}
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Ddoc-Statistics-Log-1
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Ddoc valid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: valid_XML1_3.ddoc
     */
    @Description("")
    def "ddocWithValidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("valid_XML1_3.ddoc", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "DIGIDOC_XML",
          "usrId" : "XAuthTest",
          "dur": 1334, <- Can vary, verify that its present
          "sigCt": 1,
          "vSigCt": 1,
          "sigRslt": [
             {"i":"TOTAL-PASSED", "cc":"EE", "sf" : "DIGIDOC_XML_1.3"}
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Ddoc-Statistics-Log-2
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Ddoc invalid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: ilma_kehtivuskinnituseta.ddoc
     */
    @Description("")
    def "ddocWithInvalidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("ilma_kehtivuskinnituseta.ddoc", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "DIGIDOC_XML",
          "usrId" : "XAuthTest",
          "dur": 1334, <- Can vary, verify that its present
          "sigCt": 1,
          "vSigCt": 0,
          "sigRslt": [
             {"i":"TOTAL-FAILED", "cc":"EE", "sf" : "DIGIDOC_XML_1.2"}
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Ddoc-Statistics-Log-3
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Ddoc not supported file is inserted
     *
     * Expected Result: No message in statistics as the container is not validated
     *
     * File: xroad-simple.asice
     */
    @Description("")
    def "ddocWithErrorResponse"() {
        when:
        Response response = SivaRequests.validate(RequestData.validationRequest("xroad-simple.ddoc", SignaturePolicy.POLICY_3))

        then:
        RequestErrorValidator.validate(response, RequestError.DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE)
    }

    /**
     * TestCaseID: Ddoc-Statistics-Log-4
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Ddoc with certificates from different countries.
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: Belgia_kandeavaldus_LIV.ddoc
     */
    @Description("")
    def "ddocWithSignaturesFromDifferentCountries"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("Belgia_kandeavaldus_LIV.ddoc", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
       "stats": {
          "type" : "DIGIDOC_XML",
          "usrId" : "XAuthTest",
          "dur": 1334, <- Can vary, verify that its present
          "sigCt": 2,
          "vSigCt": 1,
          "sigRslt": [
             {"i":"TOTAL-PASSED", "cc":"EE", "sf" : "DIGIDOC_XML_1.3"},
             {"i":"TOTAL-FAILED", "cc":"BE", "sf" : "DIGIDOC_XML_1.3"},
          ],
          "sigType" : "XAdES"
       }
    }        */
    }

    /**
     * TestCaseID: Pdf-Statistics-Log-1
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Pdf valid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: pades_lt_two_valid_sig.pdf
     */
    @Description("")
    def "pdfWithValidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("pades_lt_two_valid_sig.pdf", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
      "stats" : {
        "type" : "PAdES",
        "usrId" : "XAuthTest",
        "dur" : 685,
        "sigCt" : 2,
        "vSigCt" : 2,
        "sigRslt" : [
            {"i" : "TOTAL-PASSED", "cc" : "EE", "sf" : "PAdES_BASELINE_LT"},
            {"i" : "TOTAL-PASSED", "cc" : "EE", "sf" : "PAdES_BASELINE_LT"}
        ],
        "sigType" : "PAdES"
      }
    }        */
    }

    /**
     * TestCaseID: Pdf-Statistics-Log-2
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Pdf invalid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: hellopades-lt1-lt2-wrongDigestValue.pdf
     */
    @Description("")
    def "pdfWithInvalidSignatures"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("hellopades-lt1-lt2-wrongDigestValue.pdf", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
      {
      "stats" : {
        "type" : "PAdES",
        "usrId" : "XAuthTest",
        "dur" : 687,
        "sigCt" : 2,
        "vSigCt" : 0,
        "sigRslt" : [
           {"i" : "TOTAL-FAILED", "cc" : "EE", "sf" : "PAdES_BASELINE_LT"},
           {"i" : "TOTAL-FAILED", "si" : "HASH_FAILURE", "cc" : "EE", "sf" : "PAdES_BASELINE_LT"}
        ],
        "sigType" : "PAdES"
      }
    }        */
    }


    /**
     * TestCaseID: Pdf-Statistics-Log-4
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: Pdf with certificates from non Estonian countries.
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: Regulatione-signedbyco-legislators.pdf
     */
    @Description("")
    def "pdfWithSignaturesFromDifferentCountries"() {
        expect:
        postWithXAuthUsrHeader(RequestData.validationRequest("Regulatione-signedbyco-legislators.pdf", SignaturePolicy.POLICY_3), "XAuthTest")
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        Expected result:
    {
      "stats" : {
        "type" : "PAdES",
        "usrId" : "XAuthTest",
        "dur" : 830,
        "sigCt" : 2,
        "vSigCt" : 0,
        "sigRslt" : [
          {"i" : "TOTAL-FAILED", "si" : "FORMAT_FAILURE", "cc" : "BE", "sf" : "PAdES_BASELINE_B"},
          {"i" : "TOTAL-FAILED", "si" : "FORMAT_FAILURE", "cc" : "IT", "sf" : "PAdES_BASELINE_B"}
        ],
        "sigType" : "PAdES"
      }
    }        */
    }

    /**
     * TestCaseID: Asics-Statistics-Log-1
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: ASiCs valid container is validated
     *
     * Expected Result: Correct data is shown in the log with correct structure
     *
     * File: ValidBDOCinsideAsics.asics
     */
    @Description("")
    def "asicsWithValidSignatures"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidBDOCinsideAsics.asics", SignaturePolicy.POLICY_4))
                .then()
                .statusCode(HttpStatus.SC_OK)
        /*
        stats" : {
         "type" : "ASiC-S",
         "usrId" : "N/A",
         "dur" : 1566,
         "sigCt" : 0,
         "vSigCt" : 0,
         "sigRslt" : [],
         "sigType" : "N/A"
     }
 }     */
    }

    /**
     * TestCaseID: Asics-Statistics-Log-3
     *
     * TestType: Manual
     *
     * Requirement: http://open-eid.github.io/SiVa/siva3/deployment_guide/#statistics
     *
     * Title: asics invalid container is validated
     *
     * Expected Result: No message in statistics as the container is not validated
     *
     * File: TwoDataFilesAsics.asics
     */
    @Description("")
    def "asicWithErrorResponse"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TwoDataFilesAsics.asics", SignaturePolicy.POLICY_4))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
    }
}
