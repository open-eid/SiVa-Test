package ee.openeid.siva.test.allure


import io.qameta.allure.LinkAnnotation

import java.lang.annotation.*

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target([ElementType.METHOD, ElementType.TYPE])
@LinkAnnotation(type = "siva3-wiki")
@interface SivaRequirement {
    String value()
}
