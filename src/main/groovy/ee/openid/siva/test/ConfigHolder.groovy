package ee.openid.siva.test

import org.aeonbits.owner.ConfigFactory

class ConfigHolder {
    private static TestConfig conf = readConf()

    static TestConfig getConf() {
        return conf
    }

    static TestConfig readConf() {
        Properties props = new Properties()
        // Read sensitive properties
        URL sensitiveProperties = ConfigHolder.class.getResource("/sensitive.properties")
        if (sensitiveProperties) {
            sensitiveProperties.withInputStream {
                props.load(it)
            }
        }
        return ConfigFactory.create(TestConfig, props)
    }
}
