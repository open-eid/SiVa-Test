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

package ee.openeid.siva.test.util

import ee.openeid.siva.test.ConfigHolder
import ee.openeid.siva.test.TestConfig
import org.apache.commons.lang3.StringUtils

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.stream.Stream

class Utils {
    static TestConfig conf = ConfigHolder.getConf()

    static boolean isRunningInDocker() {
        if (StringUtils.containsIgnoreCase(System.getProperty('os.name'), 'linux')) {
            def cgroupFile = new File('/proc/1/cgroup')
            if (cgroupFile.exists() && cgroupFile.text.contains('docker')) {
                return true
            }
            def cgroupV2File = new File('/proc/1/mountinfo')
            if (cgroupV2File.exists() && cgroupV2File.text.contains('docker')) {
                return true
            }
        }
        return false
    }

    static boolean isLocal() {
        return !isRunningInDocker()
    }

    private static Path findFileRecursively(Path basePath, String filename) {
        if (!Files.exists(basePath) || !Files.isDirectory(basePath)) {
            throw new FileNotFoundException("Base directory '$basePath' not found or is not a directory")
        }
        try (Stream<Path> paths = Files.walk(basePath)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString() == filename)
                    .findFirst()
                    .orElse(null)
        } catch (IOException e) {
            throw new RuntimeException("Error while searching for file '$filename' in path '$basePath'", e)
        }
    }

    static byte[] readFileFromResources(String filename) {
        String basePath = conf.testFilesDirectory() ?: "src/test/resources/"
        Path foundFile = findFileRecursively(Paths.get(basePath), filename)
        if (!foundFile) {
            throw new FileNotFoundException("File $filename not found in path $basePath")
        }
        try {
            return Files.readAllBytes(foundFile)
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file '$filename' from path '$basePath'", e)
        }
    }
}
