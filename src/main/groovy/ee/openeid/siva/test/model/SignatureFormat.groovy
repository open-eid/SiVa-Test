package ee.openeid.siva.test.model

import groovy.transform.CompileStatic
import groovy.transform.Immutable

@CompileStatic
@Immutable
final class SignatureFormat {
    static final String XAdES_BASELINE_B = "XAdES_BASELINE_B"
    static final String XAdES_BASELINE_B_BES = "XAdES_BASELINE_B_BES"
    static final String XAdES_BASELINE_B_EPES = "XAdES_BASELINE_B_EPES"
    static final String XAdES_BASELINE_T = "XAdES_BASELINE_T"
    static final String XAdES_BASELINE_LT = "XAdES_BASELINE_LT"
    static final String XAdES_BASELINE_LT_TM = "XAdES_BASELINE_LT_TM"
    static final String XAdES_BASELINE_LTA = "XAdES_BASELINE_LTA"
    static final String CAdES_BASELINE_B = "CAdES_BASELINE_B"
    static final String CAdES_BASELINE_T = "CAdES_BASELINE_T"
    static final String CAdES_BASELINE_LT = "CAdES_BASELINE_LT"
    static final String CAdES_BASELINE_LTA = "CAdES_BASELINE_LTA"
    static final String PAdES_BASELINE_B = "PAdES_BASELINE_B"
    static final String PAdES_BASELINE_T = "PAdES_BASELINE_T"
    static final String PAdES_BASELINE_LT = "PAdES_BASELINE_LT"
    static final String PAdES_BASELINE_LTA = "PAdES_BASELINE_LTA"
}
