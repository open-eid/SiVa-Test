package ee.openeid.siva.test

import spock.lang.Shared
import spock.lang.Specification

abstract class GenericSpecification extends Specification {
    static BeforeAll beforeAll = new BeforeAll()

    @Shared
    TestConfig conf = ConfigHolder.getConf()
}
