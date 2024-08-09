package ee.openeid.siva.test.model

import groovy.transform.CompileStatic
import groovy.transform.Immutable

@CompileStatic
@Immutable
final class ReportType {
    static final String SIMPLE = "Simple"
    static final String DETAILED = "Detailed"
    static final String DIAGNOSTIC = "Diagnostic"
}
