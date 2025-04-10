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
