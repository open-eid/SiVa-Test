package ee.openid.siva.test

import io.qameta.allure.Allure

class Steps {

    static stepWithValue(String name, Runnable closure) {
        return Allure.step(name, closure as Allure.ThrowableRunnable)
    }
}
