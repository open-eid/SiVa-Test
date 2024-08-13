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

import ee.openeid.siva.common.DateTimeMatcher
import ee.openeid.siva.test.model.HashAlgo
import ee.openeid.siva.test.model.ReportType
import ee.openeid.siva.test.model.SignaturePolicy
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import ee.openeid.siva.test.util.RequestError
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Description
import io.qameta.allure.Link
import io.restassured.response.ValidatableResponse
import org.apache.commons.codec.binary.Base64
import org.apache.http.HttpStatus
import org.hamcrest.Matchers
import org.w3c.dom.Document
import org.w3c.dom.NodeList
import spock.lang.Ignore

import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import java.nio.charset.StandardCharsets
import java.time.ZoneId
import java.time.ZonedDateTime

import static ee.openeid.siva.integrationtest.TestData.*
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-request-interface")
class HashcodeValidationRequestSpec extends GenericSpecification {

    private ZonedDateTime testStartDate

    def setup() {
        testStartDate = ZonedDateTime.now(ZoneId.of("GMT"))
    }

    @Description("Simple report is returned")
    def "Given #reportType reportType, then simple report is returned"() {
        given:
        Map requestData = validRequestBody()
        requestData.reportType = reportType

        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithSignature(response, requestData)

        where:
        reportType            | _
        ReportType.SIMPLE     | _
        ReportType.DETAILED   | _
        ReportType.DIAGNOSTIC | _
    }

    @Description("Report type valid options")
    def "Given report type #condition, then #result"() {
        given:
        Map requestData = validRequestBody()
        requestData[key] = value
        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithSignature(response, requestData)

        where:
        key          | value    | condition       | result
        "reportType" | null     | "missing"       | "default report type is used"
        "reportType" | "SiMpLe" | "in mixed case" | "report type is case insensitive"
    }

    @Description("Data file hash algorithm case insensitivity")
    def "Given data file hash algorithm in mixed case, then algorithm is case insensitive"() {
        given:
        Map requestData = validRequestBody()
        ((requestData.signatureFiles as List<Map>).first().datafiles as List<Map>).first().hashAlgo = "sha256"
        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithSignature(response, requestData)
    }

    @Description("Correct signature policy usage")
    def "Given signature policy #condition, then #expected"() {
        given:
        Map requestData = validRequestBody()
        requestData.signaturePolicy = policy
        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyName", equalTo(expectedPolicy))
        assertSimpleReportWithSignature(response, requestData)

        where:
        policy                        | expectedPolicy                | condition | expected
        SignaturePolicy.POLICY_3.name | SignaturePolicy.POLICY_3.name | "POLv3"   | "correct policy is returned"
        SignaturePolicy.POLICY_4.name | SignaturePolicy.POLICY_4.name | "POLv4"   | "correct policy is returned"
        null                          | SignaturePolicy.POLICY_4.name | "missing" | "default policy is used"
    }

    @Description("Invalid signature policy")
    def "Given signature policy #comment, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        requestData.signaturePolicy = policy

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, *errors.collect { error -> new RequestError(errorType, error) })

        where:
        policy    | comment               | errorType        | errors
        "POLv2"   | "invalid"             | SIGNATURE_POLICY | ["Invalid signature policy: POLv2; Available abstractPolicies: [POLv3, POLv4]"]
        "POLv3.*" | "in incorrect format" | SIGNATURE_POLICY | [INVALID_SIGNATURE_POLICY]
        ""        | "empty"               | SIGNATURE_POLICY | [INVALID_POLICY_SIZE]
        'a' * 101 | "too long"            | SIGNATURE_POLICY | [INVALID_POLICY_SIZE]
    }

    @Description("Invalid input")
    def "Given request with #comment, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        requestData[key] = value

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, *errors.collect { error -> new RequestError(errorType, error) })

        where:
        key               | value      | comment                                | errorType        | errors
        "signaturePolicy" | "POLv2"    | "invalid signature policy"             | SIGNATURE_POLICY | ["Invalid signature policy: POLv2; Available abstractPolicies: [POLv3, POLv4]"]
        "signaturePolicy" | "POLv3.*"  | "signature policy in incorrect format" | SIGNATURE_POLICY | [INVALID_SIGNATURE_POLICY]
        "signaturePolicy" | ""         | "empty signature policy"               | SIGNATURE_POLICY | [INVALID_POLICY_SIZE]
        "signaturePolicy" | 'a' * 101  | "too long signature policy"            | SIGNATURE_POLICY | [INVALID_POLICY_SIZE]
        "signatureFiles"  | null       | "missing signature files"              | SIGNATURE_FILES  | [MUST_NOT_BE_EMPTY, MUST_NOT_BE_NULL]
        "signatureFiles"  | []         | "empty signature files list"           | SIGNATURE_FILES  | [MUST_NOT_BE_EMPTY]
        "reportType"      | ""         | "reportType parameter empty"           | REPORT_TYPE      | [INVALID_REPORT_TYPE]
        "reportType"      | "NotValid" | "invalid reportType"                   | REPORT_TYPE      | [INVALID_REPORT_TYPE]

    }

    @Description("Double signature policy")
    def "Given double signature policy, then last value is used"() {
        given:
        String file = Base64.encodeBase64String(Utils.readFileFromResources(MOCK_XADES_SIGNATURE_FILE))
        String requestData = "{\n" +
                "    \"reportType\": \"Simple\",\n" +
                "    \"signaturePolicy\": \"POLv3\",\n" +
                "    \"signaturePolicy\": \"POLv.5\",\n" +
                "    \"signatureFiles\": [\n" +
                "        {\n" +
                "            \"signature\": \"" + file + "\"\n" +
                "        }\n" +
                "    ]\n" +
                "}"

        when:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()

        then:
        RequestError.assertErrorResponse(response, new RequestError(SIGNATURE_POLICY, INVALID_SIGNATURE_POLICY))
    }

    @Description("Input incorrect signature")
    def "Given #comment, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        (requestData.signatureFiles as List<Map>).first().signature = value

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, new RequestError(errorType, error))

        where:
        value | comment                                                                      | errorType         | error
        "NOT.BASE64.ENCODED.VALUE"
              | "incorrect signature"                                                        | SIGNATURE_INDEX_0 | SIGNATURE_FILE_NOT_BASE64_ENCODED
        Base64.encodeBase64String("NOT_XML_FORMATTED_FILE_CONTENT".getBytes(StandardCharsets.UTF_8))
              | "not correct file type"                                                      | SIGNATURE         | SIGNATURE_FILE_MALFORMED
    }

    @Description("Input file without signature")
    def "Given signature file content without signature, then validation report is returned"() {
        given:
        String randomXmlFileWithoutSignature = "PD94bWwgdmVyc2lvbj0nMS4wJyAgZW5jb2Rpbmc9J1VURi04JyA/Pg0KPHRlc3Q+DQoJPGRhdGE+DQoJCTxzb21ldGhpbmc+c29tZSBkYXRhPC9zb21ldGhpbmc+DQoJPC9kYXRhPg0KPC90ZXN0Pg0K"
        Map requestData = validRequestBody()
        (requestData.signatureFiles as List<Map>).first().signature = randomXmlFileWithoutSignature
        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithoutSignature(response, requestData)
    }

    @Description("Data files not in request")
    def "Given data files missing in request, then validation report is returned"() {
        expect:
        Map requestData = [
                signatureFiles: [
                        [
                                signature: Base64.encodeBase64String(Utils.readFileFromResources(MOCK_XADES_SIGNATURE_FILE))
                        ]
                ]
        ]
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithSignature(response, requestData)
    }

    @Description("Empty data files list")
    def "Given empty data files list, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        (requestData.signatureFiles as List<Map>).first().datafiles = []
        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, new RequestError(DATAFILES, INVALID_DATAFILES_LIST)
        )
    }

    @Description("Invalid data file filename")
    def "Given data file filename #comment, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        ((requestData.signatureFiles as List<Map>).first().datafiles as List<Map>).first().filename = value

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, *errors.collect { error -> new RequestError(DATAFILES_FILENAME, error) })

        where:
        value     | comment    | errors
        ""        | "empty"    | [INVALID_FILENAME_SIZE, MUST_NOT_BE_EMPTY]
        null      | "missing"  | [INVALID_FILENAME, MUST_NOT_BE_EMPTY]
        'a' * 261 | "too long" | [INVALID_FILENAME_SIZE]
    }

    @Description("Data file invalid hash algorithm")
    def "Given invalid hash algorithm, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        ((requestData.signatureFiles as List<Map>).first().datafiles as List<Map>).first().hashAlgo = "INVALID_HASH_ALGORITHM"

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, new RequestError(DATAFILES_HASH_ALGO, INVALID_HASH_ALGO))
    }

    @Description("Invalid data file hash")
    def "Given data file hash #comment, then error is returned"() {
        given:
        Map requestData = validRequestBody()
        ((requestData.signatureFiles as List<Map>).first().datafiles as List<Map>).first().hash = value

        expect:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()
        RequestError.assertErrorResponse(response, *errors.collect { error -> new RequestError(DATAFILES_HASH, error) })

        where:
        value                      | comment           | errors
        null                       | "missing"         | [MUST_NOT_BE_BLANK, INVALID_BASE_64]
        ""                         | "empty"           | [MUST_NOT_BE_BLANK, INVALID_BASE_64, INVALID_HASH_SIZE]
        "NOT.BASE64.ENCODED.VALUE" | "in wrong format" | [INVALID_BASE_64]
        'P' * 1001                 | "too long"        | [INVALID_HASH_SIZE]
    }

    @Description("Double fields in datafile object")
    def "Given double fields in datafiles, then last value is used"() {
        given:
        String file = Base64.encodeBase64String(Utils.readFileFromResources(MOCK_XADES_SIGNATURE_FILE))

        String requestData = "{\n" +
                "    \"reportType\": \"Simple\",\n" +
                "    \"signaturePolicy\": \"POLv4\",\n" +
                "    \"signatureFiles\": [\n" +
                "        {\n" +
                "            \"signature\":\"" + file + "\",\n" +
                "            \"datafiles\": [\n" +
                "                {\n" +
                "                    \"filename\": \"test2.pdf\",\n" +
                "                    \"hashAlgo\": \"SHA512\",\n" +
                "                    \"hash\": \"IucjUcbRo9RkdsfdfsscwiIiplP9pSrSPr7LKln1EiI=\",\n" +
                "                    \"filename\": \"" + MOCK_XADES_DATAFILE_FILENAME + "\",\n" +
                "                    \"hashAlgo\": \"" + HashAlgo.SHA256 + "\",\n" +
                "                    \"hash\": \"" + MOCK_XADES_DATAFILE_HASH + "\"\n" +
                "                }\n" +
                "            ]\n" +
                "        }\n" +
                "    ]\n" +
                "}"

        when:
        ValidatableResponse response = SivaRequests.tryValidateHashcode(requestData).then()

        then:
        assertSignatureTotalPassed(response)
    }

    @Description("Excess data files are ignored")
    def "Given additional data file not in signature, then data file is ignored"() {
        given:
        Map requestData = validRequestBody()
        Map invalidDataFile = [
                filename: "INVALID_FILE",
                hashAlgo: HashAlgo.SHA256,
                hash    : Base64.encodeBase64String("INVALID_SIGNATURE_DIGEST".getBytes(StandardCharsets.UTF_8))
        ]
        ((requestData.signatureFiles as List<Map>).first().datafiles as List<Map>).add(invalidDataFile)

        expect:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        assertSimpleReportWithSignature(response, requestData)
    }

    @Description("Several signatures validated")
    def "Given multiple signature files, then validation report is returned and validation is passed"() {
        given:
        List<String> files = returnFiles("xades/container/")
        Map requestData = RequestData.hashcodeValidationRequest(files, null, null)

        expect:
        SivaRequests.validateHashcode(requestData)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", Matchers.is(5))
                .body("signatures.find {signatures -> signatures.signedBy == 'MÄNNIK,MARI-LIIS,47101010033'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'JÕEORG,JAAK-KRISTJAN,38001085718'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA384))
                .body("signatures.find {signatures -> signatures.signedBy == 'ŽAIKOVSKI,IGOR,37101010021'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'VÄRNICK,KRÕÕT,48812040138'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'ÅLT-DELETÈ,CØNTROLINA,48908209998'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA512))
    }

    @Description("Several signatures validated with datafile info")
    def "Given multiple signature files with datafiles, then validation report is returned and validation is passed"() {
        given:
        List<String> files = returnFiles("xades/container/")
        Map requestData = RequestData.hashcodeValidationRequest(files, null, null)
        Map requestDataWithDatafiles = addDatafiles(requestData)

        expect:
        SivaRequests.validateHashcode(requestDataWithDatafiles)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", Matchers.is(5))
                .body("signatures.find {signatures -> signatures.signedBy == 'MÄNNIK,MARI-LIIS,47101010033'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'JÕEORG,JAAK-KRISTJAN,38001085718'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA384))
                .body("signatures.find {signatures -> signatures.signedBy == 'ŽAIKOVSKI,IGOR,37101010021'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'VÄRNICK,KRÕÕT,48812040138'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'ÅLT-DELETÈ,CØNTROLINA,48908209998'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA512))
    }

    @Description("Several signatures validated one signature not valid")
    def "Given multiple signature files with one faulty, then validation report is returned"() {
        given:
        List<String> files = returnFiles("xades/container/")
        Map requestData = RequestData.hashcodeValidationRequest(files, null, null)
        Map requestDataWithDatafiles = addDatafiles(requestData)
        ((requestDataWithDatafiles.signatureFiles as List<Map>).get(files.indexOf("signatures0.xml")).datafiles as List<Map>).get(0).hash = "sjajsa"

        expect:
        SivaRequests.validateHashcode(requestDataWithDatafiles)
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validSignaturesCount", Matchers.is(4))
                .body("signatures.find {signatures -> signatures.signedBy == 'MÄNNIK,MARI-LIIS,47101010033'}.indication", is("TOTAL-FAILED"))
                .body("signatures.find {signatures -> signatures.signedBy == 'MÄNNIK,MARI-LIIS,47101010033'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'JÕEORG,JAAK-KRISTJAN,38001085718'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA384))
                .body("signatures.find {signatures -> signatures.signedBy == 'ŽAIKOVSKI,IGOR,37101010021'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'VÄRNICK,KRÕÕT,48812040138'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures.find {signatures -> signatures.signedBy == 'ÅLT-DELETÈ,CØNTROLINA,48908209998'}.signatureScopes[0].hashAlgo", is(HashAlgo.SHA512))
    }

    @Description("Hashcode validation request with request body of limit length")
    @Link("http://open-eid.github.io/SiVa/siva3/deployment_guide/#configuration-parameters")
    def "Given request body of limit length, then validation report is returned"() {
        expect:
        SivaRequests.validateHashcode(RequestData.requestWithFixedBodyLength(RequestData.hashcodeValidationRequest("Valid_XAdES_LT_TS.xml", null, null), SIVA_FILE_SIZE_LIMIT))
                .then()
                .statusCode(200)
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
    }

    @Ignore("SIVA-662")
    // TODO: Missing test file. For manual testing a file from SIVA-605 can be used.
    @Description("Signature level re-evaluation. Signatures is valid according to policy, warning is returned about signature level re-evaluation.")
    def "Given default signature policy, then signature level re-evaluation warning is returned"() {
        given:
        Map requestData = RequestData.hashcodeValidationRequest("TODO", null, null)
        when:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        then:
        response
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures", hasSize(1))
                .body("signatures[0].signatureLevel", is("ADESEAL_QC"))
                .body("signatures[0].indication", is(TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.size()", Matchers.is(2))
                .body("signatures[0].warnings[0].content", Matchers.is("The private key does not reside in a QSCD at (best) signing time!"))
                .body("signatures[0].warnings[1].content", Matchers.is("The signature level has been re-evaluated from initial UNKNOWN_QC to ADESEAL_QC by SiVa validation policy!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Ignore("SIVA-662")
    // TODO: Missing test file. For manual testing a file from SIVA-605 can be used.
    @Description("Signature level not re-evaluated in POLv3. Signatures is valid according to policy, no warning is returned about signature level re-evaluation.")
    def "Given signature policy POLv3, then no signature level re-evaluation warning is returned"() {
        given:
        Map requestData = RequestData.hashcodeValidationRequest("TODO", null, null)
        requestData.signaturePolicy = "POLv3"
        when:
        ValidatableResponse response = SivaRequests.validateHashcode(requestData).then()
        then:
        response
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures", hasSize(1))
                .body("signatures[0].signatureLevel", is("UNKNOWN_QC"))
                .body("signatures[0].indication", is(TOTAL_PASSED))
                .body("signatures[0].errors", emptyOrNullString())
                .body("signatures[0].warnings.size()", Matchers.is(1))
                .body("signatures[0].warnings[0].content", Matchers.is("The private key does not reside in a QSCD at (best) signing time!"))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    List<String> returnFiles(String filesLocation) {

        List<String> files = []
        File folder = new File("src/test/resources/" + filesLocation)
        File[] listOfFiles = folder.listFiles()

        listOfFiles.each { file ->
            if (file.isFile()) {
                files << file.name
            }
        }
        return files
    }

    private void assertSimpleReportWithSignature(ValidatableResponse response, Map request) {
        assertValidationConclusion(response, request)
        assertSignatureTotalPassed(response)
    }

    private void assertSimpleReportWithoutSignature(ValidatableResponse response, Map request) {
        assertValidationConclusion(response, request)
        response
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures", emptyOrNullString())
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
    }

    private void assertValidationConclusion(ValidatableResponse response, Map request) {
        response.statusCode(HttpStatus.SC_OK)
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("validationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("validationLevel", is(VALIDATION_LEVEL_ARCHIVAL_DATA))

        SignaturePolicy signaturePolicy = SignaturePolicy.determineValidationPolicy(request.signaturePolicy)

        response
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", equalTo(signaturePolicy.description))
                .body("policy.policyName", equalTo(signaturePolicy.name))
                .body("policy.policyUrl", equalTo(signaturePolicy.url))
    }

    private static void assertSignatureTotalPassed(ValidatableResponse response) {
        response
                .rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures", hasSize(1))
                .body("signatures[0].id", is(MOCK_XADES_SIGNATURE_ID))
                .body("signatures[0].signatureFormat", is(SIGNATURE_FORMAT_XADES_LT))
                .body("signatures[0].signatureLevel", is(SIGNATURE_LEVEL_QESIG))
                .body("signatures[0].signedBy", is(MOCK_XADES_SIGNATURE_SIGNER))
                .body("signatures[0].indication", is(TOTAL_PASSED))
                .body("signatures[0].signatureScopes", hasSize(1))
                .body("signatures[0].signatureScopes[0].name", is(MOCK_XADES_DATAFILE_FILENAME))
                .body("signatures[0].signatureScopes[0].scope", is(SIGNATURE_SCOPE_DIGEST))
                .body("signatures[0].signatureScopes[0].content", is(VALID_SIGNATURE_SCOPE_CONTENT_DIGEST))
                .body("signatures[0].signatureScopes[0].hashAlgo", is(HashAlgo.SHA256))
                .body("signatures[0].signatureScopes[0].hash", is(MOCK_XADES_DATAFILE_HASH))
                .body("signatures[0].claimedSigningTime", is(MOCK_XADES_SIGNATURE_CLAIMED_SIGNING_TIME))
                .body("signatures[0].info.bestSignatureTime", is(MOCK_XADES_SIGNATURE_BEST_SIGNATURE_TIME))
                .body("signatures[0].errors", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    private static Map validRequestBody() {
        RequestData.hashcodeValidationRequest(
                MOCK_XADES_SIGNATURE_FILE,
                SignaturePolicy.POLICY_4.name,
                ReportType.SIMPLE,
                MOCK_XADES_DATAFILE_FILENAME,
                HashAlgo.SHA256,
                MOCK_XADES_DATAFILE_HASH
        )
    }

    private static Map addDatafiles(Map requestData) {
        (requestData.signatureFiles as List<Map>).each { signatureFile ->
            byte[] file = Base64.decodeBase64(signatureFile.signature as String)
            InputStream inputStream = new ByteArrayInputStream(file)
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance()
            DocumentBuilder builder = factory.newDocumentBuilder()
            Document document = builder.parse(inputStream)
            document.documentElement.normalize()
            NodeList nList = document.getElementsByTagName("ds:Reference")

            List dataFiles = []
            for (int k = 0; k < nList.getLength() - 1; k++) {
                def node = nList.item(k)
                def algorithm = node.getChildNodes().item(0).getAttributes().getNamedItem("Algorithm").getNodeValue()
                Map dataFile = [
                        filename: node.getAttributes().getNamedItem("URI").getNodeValue(),
                        hashAlgo: algorithm.substring(algorithm.lastIndexOf("#") + 1),
                        hash    : node.getChildNodes().item(1).getFirstChild().getNodeValue()
                ]
                dataFiles << dataFile
            }
            signatureFile.datafiles = dataFiles
        }
        return requestData
    }
}
