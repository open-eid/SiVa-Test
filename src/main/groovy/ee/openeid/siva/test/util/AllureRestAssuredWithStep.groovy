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
package ee.openeid.siva.test.util

import ee.openeid.siva.test.Steps
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.filter.FilterContext
import io.restassured.response.Response
import io.restassured.specification.FilterableRequestSpecification
import io.restassured.specification.FilterableResponseSpecification

class AllureRestAssuredWithStep extends AllureRestAssured {
    @Override
    Response filter(final FilterableRequestSpecification requestSpec,
                    final FilterableResponseSpecification responseSpec,
                    final FilterContext filterContext) {
        if (requestSpec.hasProperty("allureStepName") && requestSpec?.allureStepName) {
            Response response = Steps.stepWithValue(requestSpec.allureStepName) {
                return super.filter(requestSpec, responseSpec, filterContext)
            }
            return response
        } else {
            return super.filter(requestSpec, responseSpec, filterContext)
        }
    }
}
