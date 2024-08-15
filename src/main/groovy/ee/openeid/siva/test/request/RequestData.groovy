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

package ee.openeid.siva.test.request

import ee.openeid.siva.test.util.Utils
import groovy.json.JsonOutput
import io.qameta.allure.Step
import org.apache.commons.codec.binary.Base64
import org.apache.commons.io.FilenameUtils

class RequestData {

    @Step("Validation request data from {file}")
    static Map validationRequestBase(String file, String signaturePolicy, String reportType) {
        Map data = [
                document: Base64.encodeBase64String(Utils.readFileFromResources(file)),
                filename: file
        ]
        if (signaturePolicy) {
            data.signaturePolicy = signaturePolicy
        }
        if (reportType != null) {
            data.reportType = reportType
        }
        return data
    }

    static Map validationRequest(String file, String signaturePolicy = null, String reportType = null) {
        return validationRequestBase(file, signaturePolicy, reportType)
    }

    static Map validationRequestForDDS(String file, String signaturePolicy = null, String reportType = null) {
        Map validationRequest = validationRequestBase(file, signaturePolicy, reportType)
        validationRequest.filename = FilenameUtils.getBaseName(file) + ".asice"
        return validationRequest
    }

    static Map validationRequestForDD4J(String file, String signaturePolicy = null, String reportType = null) {
        Map validationRequest = validationRequestBase(file, signaturePolicy, reportType)
        validationRequest.filename = FilenameUtils.getBaseName(file) + ".bdoc"
        return validationRequest
    }

    static Map dataFileRequest(String document, String filename) {
        Map data = [
                document: document,
                filename: filename
        ]
        return data
    }

    @Step("Data file request data from {file}")
    static Map dataFileRequestFromFile(String filename, String filenameOverride) {
        return dataFileRequest(Base64.encodeBase64String(Utils.readFileFromResources(filename)), filenameOverride)
    }

    static Map dataFileRequestFromFile(String filename) {
        return dataFileRequestFromFile(filename, filename)
    }

    @Step("Hashcode validation request data from {signatureFiles}")
    static Map hashcodeValidationRequestBase(List<String> signatureFiles, String signaturePolicy, String reportType, String dataFile, String hashAlgo, String hash) {
        List signatures = signatureFiles.collect() { signature ->
            if (dataFile == null) {
                [
                        signature: Base64.encodeBase64String(Utils.readFileFromResources(signature)),
                ]
            } else {
                [
                        signature: Base64.encodeBase64String(Utils.readFileFromResources(signature)),
                        datafiles: [
                                [
                                        filename: dataFile,
                                        hashAlgo: hashAlgo,
                                        hash    : hash
                                ]
                        ]
                ]
            }
        }

        Map<String, Object> data = [
                signatureFiles: signatures
        ]

        if (signaturePolicy) {
            data.signaturePolicy = signaturePolicy
        }
        if (reportType != null) {
            data.reportType = reportType
        }

        return data
    }

    static Map hashcodeValidationRequest(String signatureFile, String signaturePolicy, String reportType, String dataFile = null, String hashAlgo = null, String hash = null) {
        hashcodeValidationRequestBase([signatureFile], signaturePolicy, reportType, dataFile, hashAlgo, hash)
    }

    static Map hashcodeValidationRequest(List<String> signatureFiles, String signaturePolicy, String reportType, String dataFile = null, String hashAlgo = null, String hash = null) {
        hashcodeValidationRequestBase(signatureFiles, signaturePolicy, reportType, dataFile, hashAlgo, hash)
    }

    static requestWithFixedBodyLength(Map request, int expectedBodyLength) {
        int requestAsStringLength = JsonOutput.toJson(request).length()

        // Structure for extra body adds 10 additional characters
        if (requestAsStringLength > expectedBodyLength - 10) {
            throw new IllegalArgumentException("Provided request is too big to extend request with extra body.")
        }

        def loadLength = expectedBodyLength - 10 - requestAsStringLength
        request.load = 't' * loadLength

        return request as FixedBodyLengthMap
    }
}

class FixedBodyLengthMap extends LinkedHashMap {
    String toString() {
        def newMap = [:]
        newMap.putAll(this)
        newMap.load = "t * ${newMap.load.toString().length()}"
        return newMap.toString()
    }
}
