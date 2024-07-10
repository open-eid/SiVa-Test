package ee.openeid.siva.test.request

import org.apache.commons.io.FilenameUtils
import ee.openeid.siva.test.util.Utils
import io.qameta.allure.Step
import org.apache.commons.codec.binary.Base64
class RequestData {

    @Step("Validation request data from {file}")
    static Map validationRequestBase(String file, String signaturePolicy, String reportType) {
        Map data = [
                "document": Base64.encodeBase64String(Utils.readFileFromResources(file)),
                "filename": file
        ]
        if (signaturePolicy != null) {
            data.put("signaturePolicy", signaturePolicy);
        }
        if (reportType != null) {
            data.put("reportType", reportType);
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
}
