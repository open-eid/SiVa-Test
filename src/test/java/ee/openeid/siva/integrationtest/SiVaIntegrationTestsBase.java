/*
 * Copyright 2018 - 2023 Riigi Infosüsteemide Amet
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

import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.RestAssured;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;


public abstract class SiVaIntegrationTestsBase {

    protected static final String DOCUMENT_MALFORMED_OR_NOT_MATCHING_DOCUMENT_TYPE = "Document malformed or not matching documentType";
    protected static final String DOCUMENT_TYPE_NOT_ACCEPTED = "documentType is not a valid request parameter";
    protected static final String INVALID_DATA_FILE_FILENAME = "Invalid filename. Can only return data files for DDOC type containers.";
    protected static final String INVALID_FILENAME = "Invalid filename";
    protected static final String INVALID_DATAFILES_LIST = "Invalid dataFiles list";
    protected static final String INVALID_FILENAME_SIZE = "size must be between 1 and 260";
    protected static final String INVALID_HASH_SIZE = "size must be between 1 and 1000";
    protected static final String INVALID_POLICY_SIZE = "size must be between 1 and 100";
    protected static final String INVALID_REPORT_TYPE = "Invalid report type";
    protected static final String INVALID_HASH_ALGO = "Invalid hash algorithm";
    protected static final String MUST_NOT_BE_BLANK = "must not be blank";
    protected static final String MUST_NOT_BE_EMPTY = "must not be empty";
    protected static final String MUST_NOT_BE_NULL = "must not be null";
    protected static final String INVALID_BASE_64 = "Document is not encoded in a valid base64 string";
    protected static final String SIGNATURE_FILE_NOT_BASE64_ENCODED = "Signature file is not valid base64 encoded string";
    protected static final String SIGNATURE_MALFORMED = "Signature file malformed";
    protected static final String INVALID_SIGNATURE_POLICY = "Invalid signature policy";
    protected static final String SIGNATURE_FILE_MALFORMED = "Signature file malformed";
    protected static final String DOCUMENT_TYPE = "documentType";
    protected static final String FILENAME = "filename";
    protected static final String DOCUMENT = "document";
    protected static final String SIGNATURE_POLICY = "signaturePolicy";
    protected static final String REPORT_TYPE = "reportType";
    protected static final String SIGNATURE_INDEX_0 = "signatureFiles[0].signature";
    protected static final String SIGNATURE = "signatureFiles.signature";
    protected static final String SIGNATURE_FILES = "signatureFiles";
    protected static final String DATAFILES = "signatureFiles[0].datafiles";
    protected static final String DATAFILES_FILENAME = "signatureFiles[0].datafiles[0].filename";
    protected static final String DATAFILES_HASH = "signatureFiles[0].datafiles[0].hash";
    protected static final String DATAFILES_HASH_ALGO = "signatureFiles[0].datafiles[0].hashAlgo";
    private static final String TEST_FILE_BASE = "src/test/resources/";

    protected static final String VALID_SIGNATURE_POLICY_3 = "POLv3";
    protected static final String VALID_SIGNATURE_POLICY_4 = "POLv4";

    protected static final String SMALL_CASE_VALID_SIGNATURE_POLICY_3 = "polv3";

    protected static final String POLICY_3_DESCRIPTION = "Policy for validating Electronic Signatures and Electronic Seals " +
            "regardless of the legal type of the signature or seal (according to Regulation (EU) No 910/2014, aka eIDAS), " +
            "i.e. the fact that the electronic signature or electronic seal is either Advanced electronic Signature (AdES)," +
            " AdES supported by a Qualified Certificate (AdES/QC) or a Qualified electronic Signature (QES) does not change " +
            "the total validation result of the signature. Signatures which are not compliant with ETSI standards (referred by" +
            " Regulation (EU) No 910/2014) may produce unknown or invalid validation result. Validation process is based on " +
            "eIDAS Article 32, Commission Implementing Decision (EU) 2015/1506 and referred ETSI standards.";
    protected static final String POLICY_4_DESCRIPTION = "Policy according most common requirements of Estonian Public " +
            "Administration, to validate Qualified Electronic Signatures and Electronic Seals with Qualified Certificates" +
            " (according to Regulation (EU) No 910/2014, aka eIDAS). I.e. signatures that have been recognized as Advanced" +
            " electronic Signatures (AdES) and AdES supported by a Qualified Certificate (AdES/QC) do not produce a positive" +
            " validation result, with exception for seals, where AdES/QC and above will produce positive result. Signatures" +
            " and Seals which are not compliant with ETSI standards (referred by eIDAS) may produce unknown or invalid validation" +
            " result. Validation process is based on eIDAS Article 32 and referred ETSI standards.";

    protected static final String POLICY_3_URL = "http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv3";
    protected static final String POLICY_4_URL = "http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4";

    protected abstract String getTestFilesDirectory();

    protected static Map<String, Object> yamlMaps;

    static {
        Yaml yaml = new Yaml();
        try {
            String path = SiVaIntegrationTestsBase.class.getResource("/application-test.yml").getPath();
            yamlMaps = yaml.load(new FileInputStream(new File(path)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        RestAssured.useRelaxedHTTPSValidation();
        RestAssured.filters(new AllureRestAssured());
    }

    public String createUrl(String endpoint) {
        LinkedHashMap sivaMap = (LinkedHashMap) yamlMaps.get("siva");
        String contextPath = Optional.ofNullable((String) sivaMap.get("application-context-path")).orElse("");
        return sivaMap.get("protocol") + "://" + sivaMap.get("hostname") + ":" + sivaMap.get("port") + contextPath + endpoint;
    }

    protected byte[] readFileFromTestResources(String filename) {
        return readFileFromPath((TEST_FILE_BASE) + getTestFilesDirectory() + filename);
    }

    protected static byte[] readFileFromPath(String pathName) {
        try {
            return Files.readAllBytes(FileSystems.getDefault().getPath(pathName));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
