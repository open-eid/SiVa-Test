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
final class ContainerFormat {
    // From DSS
    // https://github.com/esig/dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/ASiCContainerType.java
    static final String ASiC_E = "ASiC-E"
    static final String ASiC_S = "ASiC-S"

    // Estonian specific DDOC
    static final String DIGIDOC_XML_1_0 = "DIGIDOC_XML_1.0"
    static final String DIGIDOC_XML_1_0_hashcode = "DIGIDOC_XML_1.0_hashcode"
    static final String DIGIDOC_XML_1_1 = "DIGIDOC_XML_1.1"
    static final String DIGIDOC_XML_1_1_hashcode = "DIGIDOC_XML_1.1_hashcode"
    static final String DIGIDOC_XML_1_2 = "DIGIDOC_XML_1.2"
    static final String DIGIDOC_XML_1_2_hashcode = "DIGIDOC_XML_1.2_hashcode"
    static final String DIGIDOC_XML_1_3 = "DIGIDOC_XML_1.3"
    static final String DIGIDOC_XML_1_3_hashcode = "DIGIDOC_XML_1.3_hashcode"
}
