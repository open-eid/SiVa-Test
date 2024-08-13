package ee.openeid.siva.test.model

import groovy.transform.CompileStatic
import groovy.transform.Immutable

@CompileStatic
@Immutable
final class HashAlgo {
    static final String SHA224 = "SHA224"
    static final String SHA256 = "SHA256"
    static final String SHA384 = "SHA384"
    static final String SHA512 = "SHA512"
}
