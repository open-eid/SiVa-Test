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

package ee.openeid.siva.test

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

    @Key("allure-rest-request-limit")
    Integer allureRestRequestLimit()

    @Key("allure-rest-response-limit")
    Integer allureRestResponseLimit()
}
