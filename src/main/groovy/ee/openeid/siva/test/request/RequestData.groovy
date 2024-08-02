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
        if (signaturePolicy != null) {
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

    @Step("Data file request data from {file}")
    static Map dataFileRequest(String file) {
        Map data = [
                document: Base64.encodeBase64String(Utils.readFileFromResources(file)),
                filename: file
        ]
        return data
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

        Map data = [
                signatureFiles : signatures,
                signaturePolicy: signaturePolicy,
                reportType     : reportType,
        ]
        return data
    }

    static Map hashcodeValidationRequest(String signatureFile, String signaturePolicy, String reportType, String dataFile, String hashAlgo, String hash) {
        hashcodeValidationRequestBase([signatureFile], signaturePolicy, reportType, dataFile, hashAlgo, hash)
    }

    static Map hashcodeValidationRequestSimple(String signatureFile, String signaturePolicy, String reportType) {
        hashcodeValidationRequestBase([signatureFile], signaturePolicy, reportType, null, null, null)
    }

    static Map hashcodeValidationRequestSimple(List<String> signatureFiles, String signaturePolicy, String reportType) {
        hashcodeValidationRequestBase(signatureFiles, signaturePolicy, reportType, null, null, null)
    }
}
