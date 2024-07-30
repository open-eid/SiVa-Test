package ee.openeid.siva.test.util

import ee.openeid.siva.test.ConfigHolder
import ee.openeid.siva.test.TestConfig

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.stream.Stream

class Utils {
    static TestConfig conf = ConfigHolder.getConf()

    static boolean isRunningInDocker() {
        def cgroupFile = new File('/proc/1/cgroup')
        // Check if the OS is Linux and /proc/1/cgroup exists
        if (System.getProperty('os.name').toLowerCase().contains('linux') && cgroupFile.exists()) {
            // Check if /proc/1/cgroup contents contain the string "docker"
            return cgroupFile.text.contains('docker')
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

    static byte[] readFileFromResources(String filename) throws IOException {
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
