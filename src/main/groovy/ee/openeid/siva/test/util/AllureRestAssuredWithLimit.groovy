/*
 * Copyright 2024 - 2025 Riigi Infosüsteemi Amet
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

/*
 *  Copyright 2016-2024 Qameta Software Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Original work licensed under the Apache License, Version 2.0
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Modifications  licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL
 * https://joinup.ec.europa.eu/software/page/eupl
 */

package ee.openeid.siva.test.util

import ee.openeid.siva.test.ConfigHolder
import io.qameta.allure.attachment.DefaultAttachmentProcessor
import io.qameta.allure.attachment.FreemarkerAttachmentRenderer
import io.qameta.allure.attachment.http.HttpRequestAttachment
import io.qameta.allure.attachment.http.HttpResponseAttachment
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.filter.FilterContext
import io.restassured.internal.NameAndValue
import io.restassured.internal.support.Prettifier
import io.restassured.response.Response
import io.restassured.specification.FilterableRequestSpecification
import io.restassured.specification.FilterableResponseSpecification

import static io.qameta.allure.attachment.http.HttpRequestAttachment.Builder.create as req_create
import static io.qameta.allure.attachment.http.HttpResponseAttachment.Builder.create as res_create
import static java.util.Optional.ofNullable

/**
 * Copy of io.qameta.allure.restassured.AllureRestAssured modified with request and response attachment size limiters
 */
class AllureRestAssuredWithLimit extends AllureRestAssured {

    private static final String HIDDEN_PLACEHOLDER = "[ BLACKLISTED ]"

    private String requestTemplatePath = "http-request.ftl"
    private String responseTemplatePath = "http-response.ftl"
    private String requestAttachmentName = "Request"
    private String responseAttachmentName

    AllureRestAssured setRequestTemplate(final String templatePath) {
        this.requestTemplatePath = templatePath
        return this
    }

    AllureRestAssured setResponseTemplate(final String templatePath) {
        this.responseTemplatePath = templatePath
        return this
    }

    AllureRestAssured setRequestAttachmentName(final String requestAttachmentName) {
        this.requestAttachmentName = requestAttachmentName
        return this
    }

    AllureRestAssured setResponseAttachmentName(final String responseAttachmentName) {
        this.responseAttachmentName = responseAttachmentName
        return this
    }

    @Override
    Response filter(final FilterableRequestSpecification requestSpec,
                    final FilterableResponseSpecification responseSpec,
                    final FilterContext filterContext) {
        final Prettifier prettifier = new Prettifier()
        final String url = requestSpec.getURI()

        final Set<String> hiddenHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER)
        hiddenHeaders.addAll(Objects.requireNonNull(requestSpec.getConfig().getLogConfig().blacklistedHeaders()))

        final HttpRequestAttachment.Builder requestAttachmentBuilder = req_create(requestAttachmentName, url)
                .setMethod(requestSpec.getMethod())
                .setHeaders(toMapConverter(requestSpec.getHeaders(), hiddenHeaders))
                .setCookies(toMapConverter(requestSpec.getCookies(), new HashSet<>()))

        if (Objects.nonNull(requestSpec.getBody())) {
            // Limit request attachment size
            if (ConfigHolder.getConf().allureRestRequestLimit() != null) {
                int requestLimit = ConfigHolder.getConf().allureRestRequestLimit()
                int requestBodyLength = requestSpec.getBody().toString().length()
                if (requestBodyLength > requestLimit) {
                    requestAttachmentBuilder.setBody(requestSpec.getBody().toString().substring(0, requestLimit) +
                            "...\n\n The request body length (${requestBodyLength}) exceeds the limit (${requestLimit}) for report attachment.")
                } else {
                    requestAttachmentBuilder.setBody(prettifier.getPrettifiedBodyIfPossible(requestSpec))
                }
            } else {
                requestAttachmentBuilder.setBody(prettifier.getPrettifiedBodyIfPossible(requestSpec))
            }
        }

        if (Objects.nonNull(requestSpec.getFormParams())) {
            requestAttachmentBuilder.setFormParams(requestSpec.getFormParams())
        }

        final HttpRequestAttachment requestAttachment = requestAttachmentBuilder.build()

        new DefaultAttachmentProcessor().addAttachment(
                requestAttachment,
                new FreemarkerAttachmentRenderer(requestTemplatePath)
        )

        final Response response = filterContext.next(requestSpec, responseSpec)

        final String attachmentName = ofNullable(responseAttachmentName)
                .orElse(response.getStatusLine())

        final HttpResponseAttachment.Builder responseAttachmentBuilder = res_create(attachmentName)
                .setResponseCode(response.getStatusCode())
                .setHeaders(toMapConverter(response.getHeaders(), hiddenHeaders))

        // Limit response attachment size
        if (ConfigHolder.getConf().allureRestResponseLimit() != null) {
            int responseLimit = ConfigHolder.getConf().allureRestResponseLimit()
            int requestBodyLength = response.getBody().toString().length()
            if (requestBodyLength > responseLimit) {
                responseAttachmentBuilder.setBody(response.getBody().toString().substring(0, responseLimit) +
                        "...\n\n The response body (${requestBodyLength}) exceeds the limit (${responseLimit}) for report attachment.")
            } else {
                responseAttachmentBuilder.setBody(prettifier.getPrettifiedBodyIfPossible(response, response.getBody()))
            }
        } else {
            responseAttachmentBuilder.setBody(prettifier.getPrettifiedBodyIfPossible(response, response.getBody()))
        }

        final HttpResponseAttachment responseAttachment = responseAttachmentBuilder.build()

        new DefaultAttachmentProcessor().addAttachment(
                responseAttachment,
                new FreemarkerAttachmentRenderer(responseTemplatePath)
        )

        return response
    }

    private static Map<String, String> toMapConverter(final Iterable<? extends NameAndValue> items,
                                                      final Set<String> toHide) {
        final Map<String, String> result = new HashMap<>()
        items.forEach(h -> result.put(h.getName(), toHide.contains(h.getName()) ? HIDDEN_PLACEHOLDER : h.getValue()))
        return result
    }

    @Override
    int getOrder() {
        return Integer.MAX_VALUE
    }
}
