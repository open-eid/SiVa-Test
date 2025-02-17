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

package ee.openeid.siva.test.model

import groovy.transform.CompileStatic
import groovy.transform.Immutable

@CompileStatic
@Immutable
final class SignatureLevel {
    // DSS
    // https://github.com/esig/dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/SignatureQualification.java
    static final String ADESEAL = "ADESEAL"
    static final String ADESEAL_QC = "ADESEAL_QC"
    static final String ADESIG = "ADESIG"
    static final String ADESIG_QC = "ADESIG_QC"
    static final String INDETERMINATE_ADESEAL = "INDETERMINATE_ADESEAL"
    static final String INDETERMINATE_ADESEAL_QC = "INDETERMINATE_ADESEAL_QC"
    static final String INDETERMINATE_ADESIG = "INDETERMINATE_ADESIG"
    static final String INDETERMINATE_ADESIG_QC = "INDETERMINATE_ADESIG_QC"
    static final String INDETERMINATE_QESEAL = "INDETERMINATE_QESEAL"
    static final String INDETERMINATE_QESIG = "INDETERMINATE_QESIG"
    static final String INDETERMINATE_UNKNOWN = "INDETERMINATE_UNKNOWN"
    static final String INDETERMINATE_UNKNOWN_QC = "INDETERMINATE_UNKNOWN_QC"
    static final String INDETERMINATE_UNKNOWN_QC_QSCD = "INDETERMINATE_UNKNOWN_QC_QSCD"
    static final String NA = "NA"
    static final String NOT_ADES = "NOT_ADES"
    static final String NOT_ADES_QC = "NOT_ADES_QC"
    static final String NOT_ADES_QC_QSCD = "NOT_ADES_QC_QSCD"
    static final String QESEAL = "QESEAL"
    static final String QESIG = "QESIG"
    static final String UNKNOWN = "UNKNOWN"
    static final String UNKNOWN_QC = "UNKNOWN_QC"
    static final String UNKNOWN_QC_QSCD = "UNKNOWN_QC_QSCD"

}
