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

package ee.openeid.siva.test.model

enum RequestError {
    FILENAME_EMPTY(key: "filename", message: CommonError.MUST_NOT_BE_EMPTY),
    FILENAME_INVALID(key: "filename", message: "Invalid filename"),
    FILENAME_INVALID_SIZE(key: "filename", message: SizeError.getSizeError(260)),

    DATA_FILE_FILENAME_INVALID(key: "filename", message: "Invalid filename. Can only return data files for DDOC type containers."),

    DATAFILES_LIST_INVALID(key: "signatureFiles[0].datafiles", message: "Invalid dataFiles list"),

    DATAFILE_FILENAME_EMPTY(key: "signatureFiles[0].datafiles[0].filename", message: CommonError.MUST_NOT_BE_EMPTY),
    DATAFILE_FILENAME_INVALID(key: "signatureFiles[0].datafiles[0].filename", message: "Invalid filename"),
    DATAFILE_FILENAME_INVALID_SIZE(key: "signatureFiles[0].datafiles[0].filename", message: SizeError.getSizeError(260)),

    DATAFILE_HASH_ALGO_INVALID(key: "signatureFiles[0].datafiles[0].hashAlgo", message: "Invalid hash algorithm"),

    DATAFILE_HASH_BLANK(key: "signatureFiles[0].datafiles[0].hash", message: CommonError.MUST_NOT_BE_BLANK),
    DATAFILE_HASH_INVALID_BASE_64(key: "signatureFiles[0].datafiles[0].hash", message: "Document is not encoded in a valid base64 string"),
    DATAFILE_HASH_INVALID_SIZE(key: "signatureFiles[0].datafiles[0].hash", message: SizeError.getSizeError(1000)),

    DOCUMENT_BLANK(key: "document", message: CommonError.MUST_NOT_BE_BLANK),
    DOCUMENT_INVALID_BASE_64(key: "document", message: "Document is not encoded in a valid base64 string"),
    DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE(key: "document", message: "Document malformed or not matching documentType"),

    DOCUMENT_TYPE_INVALID(key: "documentType", message: "documentType is not a valid request parameter"),

    REPORT_TYPE_INVALID(key: "reportType", message: "Invalid report type"),

    SIGNATURE_FILES_EMPTY(key: "signatureFiles", message: CommonError.MUST_NOT_BE_EMPTY),
    SIGNATURE_FILES_NULL(key: "signatureFiles", message: CommonError.MUST_NOT_BE_NULL),

    SIGNATURE_FILE_MALFORMED(key: "signatureFiles.signature", message: "Signature file malformed"),
    SIGNATURE_FILE_NOT_BASE64(key: "signatureFiles[0].signature", message: "Signature file is not valid base64 encoded string"),

    SIGNATURE_POLICY_INVALID(key: "signaturePolicy", message: "Invalid signature policy"),
    SIGNATURE_POLICY_INVALID_SIZE(key: "signaturePolicy", message: SizeError.getSizeError(100)),

    // TODO: Investigate if these errors are used and should be covered by tests.
    // "Invalid filename extension. Only xml files accepted."
    // "Invalid filename format"
    // "Invalid SignatureFiles format"
    // "Invalid datafile filename format"
    // "Document does not meet the requirements"
    // "Unfortunately there was an error validating your document"

    final String key
    final String message

    RequestError(Map<String, String> params) {
        this.key = params.key
        this.message = params.message
    }

}

final class CommonError {
    static final String MUST_NOT_BE_BLANK = "must not be blank"
    static final String MUST_NOT_BE_EMPTY = "must not be empty"
    static final String MUST_NOT_BE_NULL = "must not be null"

}

class SizeError {
    static final String message = "size must be between 1 and "

    static String getSizeError(int maxSize) {
        return message + maxSize.toString()
    }
}
