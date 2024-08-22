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
    FILENAME_EMPTY("filename", CommonError.MUST_NOT_BE_EMPTY),
    FILENAME_INVALID("filename", "Invalid filename"),
    FILENAME_INVALID_SIZE("filename", SizeError.getSizeError(260)),

    DATA_FILE_FILENAME_INVALID("filename", "Invalid filename. Can only return data files for DDOC type containers."),

    DATAFILES_LIST_INVALID("signatureFiles[0].datafiles", "Invalid dataFiles list"),

    DATAFILE_FILENAME_EMPTY("signatureFiles[0].datafiles[0].filename", CommonError.MUST_NOT_BE_EMPTY),
    DATAFILE_FILENAME_INVALID("signatureFiles[0].datafiles[0].filename", "Invalid filename"),
    DATAFILE_FILENAME_INVALID_SIZE("signatureFiles[0].datafiles[0].filename", SizeError.getSizeError(260)),

    DATAFILE_HASH_ALGO_INVALID("signatureFiles[0].datafiles[0].hashAlgo", "Invalid hash algorithm"),

    DATAFILE_HASH_BLANK("signatureFiles[0].datafiles[0].hash", CommonError.MUST_NOT_BE_BLANK),
    DATAFILE_HASH_INVALID_BASE_64("signatureFiles[0].datafiles[0].hash", "Document is not encoded in a valid base64 string"),
    DATAFILE_HASH_INVALID_SIZE("signatureFiles[0].datafiles[0].hash", SizeError.getSizeError(1000)),

    DOCUMENT_BLANK("document", CommonError.MUST_NOT_BE_BLANK),
    DOCUMENT_INVALID_BASE_64("document", "Document is not encoded in a valid base64 string"),
    DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE("document", "Document malformed or not matching documentType"),

    DOCUMENT_TYPE_INVALID("documentType", "documentType is not a valid request parameter"),

    REPORT_TYPE_INVALID("reportType", "Invalid report type"),

    SIGNATURE_FILES_EMPTY("signatureFiles", CommonError.MUST_NOT_BE_EMPTY),
    SIGNATURE_FILES_NULL("signatureFiles", CommonError.MUST_NOT_BE_NULL),

    SIGNATURE_FILE_MALFORMED("signatureFiles.signature", "Signature file malformed"),
    SIGNATURE_FILE_NOT_BASE64("signatureFiles[0].signature", "Signature file is not valid base64 encoded string"),

    SIGNATURE_POLICY_INVALID("signaturePolicy", "Invalid signature policy"),
    SIGNATURE_POLICY_INVALID_SIZE("signaturePolicy", SizeError.getSizeError(100)),

    // TODO: Investigate if these errors are used and should be covered by tests.
    // "Invalid filename extension. Only xml files accepted."
    // "Invalid filename format"
    // "Invalid SignatureFiles format"
    // "Invalid datafile filename format"
    // "Document does not meet the requirements"
    // "Unfortunately there was an error validating your document"

    final String key
    final String message

    RequestError(String key, String message) {
        this.key = key
        this.message = message
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
