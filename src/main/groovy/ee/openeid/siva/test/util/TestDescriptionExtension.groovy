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

import io.qameta.allure.Description
import org.spockframework.runtime.extension.IGlobalExtension
import org.spockframework.runtime.extension.IMethodInterceptor
import org.spockframework.runtime.extension.IMethodInvocation
import org.spockframework.runtime.model.FeatureInfo
import org.spockframework.runtime.model.MethodInfo
import org.spockframework.runtime.model.SpecInfo

class TestDescriptionExtension implements IGlobalExtension {

    private static final String OUTPUT_FILE = "test-descriptions.md"
    private Map<String, List<String>> testDescriptions = [:]

    @Override
    void start() {
        // Overwrite the file at the start of the tests
        new File(OUTPUT_FILE).withWriter { writer ->
            writer.write("# Test Descriptions\n\n")
        }
    }

    @Override
    void visitSpec(SpecInfo spec) {
        spec.allFeatures.each { FeatureInfo feature ->
            feature.featureMethod.addInterceptor(new IMethodInterceptor() {
                @Override
                void intercept(IMethodInvocation invocation) throws Throwable {
                    captureTestDescription(feature, invocation.method, spec.filename)
                    invocation.proceed()
                }
            })
        }
    }

    @Override
    void stop() {
        // Write collected test descriptions to the file
        writeTestDescriptionsToFile()
    }

    void captureTestDescription(FeatureInfo feature, MethodInfo method, String filename) {
        // Add test case name
        def description = "### Test Case: ${feature.name}\n\n"

        // Add Allure description if present
        def methodReflection = method.reflection
        if (methodReflection.isAnnotationPresent(Description)) {
            Description allureDescription = methodReflection.getAnnotation(Description)
            description += "**Description:** ${allureDescription.value()}\n\n"
        }

        // Add test stages description
        feature.blocks.each { block ->
            def blockText = block.texts.join(" ")
            description += "**${block.kind.name().capitalize()}:** ${blockText}\n\n"
        }

        if (!testDescriptions.containsKey(filename)) {
            testDescriptions[filename] = []
        }
        testDescriptions[filename] << (description as String)
    }

    void writeTestDescriptionsToFile() {
        new File(OUTPUT_FILE).withWriterAppend { writer ->
            testDescriptions.each { filename, descriptions ->
                writer.write("## Test File: ${filename}\n\n")
                descriptions.each { description ->
                    writer.write(description)
                }
                writer.write("\n") // Add a newline for better readability
            }
        }
    }
}
