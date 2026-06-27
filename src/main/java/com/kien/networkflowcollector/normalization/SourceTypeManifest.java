package com.kien.networkflowcollector.normalization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;

final class SourceTypeManifest {

    static final String DEFAULT_RESOURCE = "META-INF/nfc/source-types.json";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private SourceTypeManifest() {}

    static Set<String> loadDefault() {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = SourceTypeManifest.class.getClassLoader();
        }
        return load(classLoader, DEFAULT_RESOURCE);
    }

    static Set<String> load(ClassLoader classLoader, String resourceName) {
        try {
            Enumeration<URL> resources = classLoader.getResources(resourceName);
            Set<String> sourceTypes = new LinkedHashSet<>();
            while (resources.hasMoreElements()) {
                sourceTypes.addAll(read(resources.nextElement()));
            }
            return Set.copyOf(sourceTypes);
        } catch (IOException e) {
            throw new NormalizerRegistryException("Unable to load source type manifest " + resourceName, e);
        }
    }

    private static Set<String> read(URL resource) throws IOException {
        JsonNode root;
        try (InputStream input = resource.openStream()) {
            root = OBJECT_MAPPER.readTree(input);
        }
        JsonNode sourceTypes = sourceTypesNode(root, resource);
        Set<String> values = new LinkedHashSet<>();
        for (JsonNode sourceType : sourceTypes) {
            if (!sourceType.isTextual() || sourceType.asText().isBlank()) {
                throw new NormalizerRegistryException(
                        "Source type manifest contains a non-text source type in " + resource);
            }
            values.add(sourceType.asText());
        }
        return values;
    }

    private static JsonNode sourceTypesNode(JsonNode root, URL resource) {
        if (root.isArray()) {
            return root;
        }
        if (root.isObject()) {
            if (root.has("sourceTypes")) {
                return requireArray(root.get("sourceTypes"), resource, "sourceTypes");
            }
            if (root.has("source_types")) {
                return requireArray(root.get("source_types"), resource, "source_types");
            }
            if (root.has("requiredSourceTypes")) {
                return requireArray(root.get("requiredSourceTypes"), resource, "requiredSourceTypes");
            }
        }
        throw new NormalizerRegistryException(
                "Source type manifest must be an array or object with sourceTypes in " + resource);
    }

    private static JsonNode requireArray(JsonNode node, URL resource, String fieldName) {
        if (!node.isArray()) {
            throw new NormalizerRegistryException(
                    "Source type manifest field " + fieldName + " must be an array in " + resource);
        }
        return node;
    }
}
