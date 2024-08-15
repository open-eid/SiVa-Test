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

import groovy.transform.CompileStatic
import groovy.transform.Immutable

@CompileStatic
@Immutable
final class SignatureFormat {
    // DSS
    // https://github.com/esig/dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/SignatureLevel.java
    static final String CAdES_A = "CAdES_A"
    static final String CAdES_BASELINE_B = "CAdES_BASELINE_B"
    static final String CAdES_BASELINE_LT = "CAdES_BASELINE_LT"
    static final String CAdES_BASELINE_LTA = "CAdES_BASELINE_LTA"
    static final String CAdES_BASELINE_T = "CAdES_BASELINE_T"
    static final String CAdES_BES = "CAdES_BES"
    static final String CAdES_C = "CAdES_C"
    static final String CAdES_EPES = "CAdES_EPES"
    static final String CAdES_LT = "CAdES_LT"
    static final String CAdES_T = "CAdES_T"
    static final String CAdES_X = "CAdES_X"
    static final String CAdES_XL = "CAdES_XL"
    static final String CMS_NOT_ETSI = "CMS_NOT_ETSI"
    static final String JAdES_BASELINE_B = "JAdES_BASELINE_B"
    static final String JAdES_BASELINE_LT = "JAdES_BASELINE_LT"
    static final String JAdES_BASELINE_LTA = "JAdES_BASELINE_LTA"
    static final String JAdES_BASELINE_T = "JAdES_BASELINE_T"
    static final String JSON_NOT_ETSI = "JSON_NOT_ETSI"
    static final String PAdES_BASELINE_B = "PAdES_BASELINE_B"
    static final String PAdES_BASELINE_LT = "PAdES_BASELINE_LT"
    static final String PAdES_BASELINE_LTA = "PAdES_BASELINE_LTA"
    static final String PAdES_BASELINE_T = "PAdES_BASELINE_T"
    static final String PDF_NOT_ETSI = "PDF_NOT_ETSI"
    static final String PKCS7_B = "PKCS7_B"
    static final String PKCS7_LT = "PKCS7_LT"
    static final String PKCS7_LTA = "PKCS7_LTA"
    static final String PKCS7_T = "PKCS7_T"
    static final String UNKNOWN = "UNKNOWN"
    static final String XAdES_A = "XAdES_A"
    static final String XAdES_BASELINE_B = "XAdES_BASELINE_B"
    static final String XAdES_BASELINE_LT = "XAdES_BASELINE_LT"
    static final String XAdES_BASELINE_LTA = "XAdES_BASELINE_LTA"
    static final String XAdES_BASELINE_T = "XAdES_BASELINE_T"
    static final String XAdES_BES = "XAdES_BES"
    static final String XAdES_C = "XAdES_C"
    static final String XAdES_EPES = "XAdES_EPES"
    static final String XAdES_LT = "XAdES_LT"
    static final String XAdES_T = "XAdES_T"
    static final String XAdES_X = "XAdES_X"
    static final String XAdES_XL = "XAdES_XL"
    static final String XML_NOT_ETSI = "XML_NOT_ETSI"

    // Additional SD-DSS
    // https://github.com/open-eid/sd-dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/SignatureLevel.java
    static final String XAdES_BASELINE_B_EPES = "XAdES_BASELINE_B_EPES"
    static final String XAdES_BASELINE_LT_TM = "XAdES_BASELINE_LT_TM"

    // Additional
    static final String XAdES_BASELINE_B_BES = "XAdES_BASELINE_B_BES"
    static final String SK_XML = "SK_XML_1.0"
    static final String DIGIDOC_XML_1_1 = "DIGIDOC_XML_1.1"
    static final String DIGIDOC_XML_1_2 = "DIGIDOC_XML_1.2"
    static final String DIGIDOC_XML_1_3 = "DIGIDOC_XML_1.3"
}
