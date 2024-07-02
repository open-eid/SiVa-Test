package ee.openid.siva.test

import org.aeonbits.owner.Config
import org.aeonbits.owner.Config.Key
import org.aeonbits.owner.Config.Sources

@Sources(["classpath:application.properties"])
interface TestConfig extends Config {

    @Key("siva.application-context-path")
    String sivaContextPath()

    @Key("siva.hostname")
    String sivaHostname()

    @Key("siva.port")
    String sivaPort()

    @Key("siva.protocol")
    String sivaProtocol()

    @Key("test-files-directory")
    String testFilesDirectory()

    @Key("rest-assured-console-logging")
    Boolean restAssuredConsoleLogging()
}
