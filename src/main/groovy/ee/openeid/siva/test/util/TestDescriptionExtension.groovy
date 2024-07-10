package ee.openeid.siva.test.util
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
        def description = "### Test Case: ${feature.name}\n\n"
        feature.blocks.each { block ->
            def blockText = block.texts.join(" ")
            description += "**${block.kind.name().capitalize()}:** ${blockText}\n\n"
        }
        if (!testDescriptions.containsKey(filename)) {
            testDescriptions[filename] = []
        }
        testDescriptions[filename] << description
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
