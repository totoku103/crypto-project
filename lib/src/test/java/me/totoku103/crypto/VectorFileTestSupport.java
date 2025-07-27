package me.totoku103.crypto;


import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VectorFileTestSupport {
    protected static String getSplitAndValue(String line) {
        final String[] split = line.split("=");
        if (split.length == 1) return "";
        else if (split.length == 2) return split[1].trim();
        else return "";
    }

    protected static File getVectorFile(String path) {
        final URL resource = VectorFileTestSupport.class.getResource(path);
        if (resource == null) throw new RuntimeException("resource is null");

        final File vectorFile = new File(resource.getFile());
        if (!vectorFile.isFile()) throw new RuntimeException("vector file is not a file");

        return vectorFile;
    }

    protected static List<String> getContents(File file) throws IOException {
        return Files.readAllLines(file.toPath());
    }

    protected static <T> List<Map<String, String>> extractValue(String splitWord, List<String> contents) {
        final List<Map<String, String>> result = new ArrayList<>();

        Map<String, String> count = null;
        for (String line : contents) {
            final String trimLines = line.trim();
            if (trimLines.isEmpty()) {
                if (count != null) {
                    result.add(count);
                    count = new HashMap<>();
                    continue;
                } else {
                    count = new HashMap<>();
                }
            }

            final String[] split = trimLines.split(splitWord);
            if (split.length == 1) continue;
            else if (split.length == 2) {
                if (count == null) count = new HashMap<>();
                count.put(split[0].toUpperCase().trim(), split[1].toUpperCase().trim());
            }
        }
        return result;
    }
}
