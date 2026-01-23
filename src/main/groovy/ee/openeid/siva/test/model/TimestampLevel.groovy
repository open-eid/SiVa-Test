/*
 * Copyright 2025 - 2026 Riigi Infosüsteemi Amet
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
final class TimestampLevel {
    // DSS
    // https://github.com/esig/dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/TimestampQualification.java
    static final String QTSA = "QTSA"
    static final String TSA = "TSA"
    static final String NA = "NA"
}
