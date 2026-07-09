package com.kien.networkflowcollector.plugins.netflow.template;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TemplateCache")
class TemplateCacheTest {

    private TemplateCache cache;

    @BeforeEach
    void setUp() {
        cache = new TemplateCache();
    }

    private TemplateRecord sampleTemplate(int templateId) {
        return new TemplateRecord(templateId,
                List.of(TemplateField.standard(8, 4), TemplateField.standard(12, 4)),
                false);
    }

    // Test happy path: put/get returns a stored NetFlow v9 template.
    @Test
    @DisplayName("put and get → returns stored template")
    void putAndGet_returnsStoredTemplate() {
        TemplateRecord tmpl = sampleTemplate(256);
        cache.put("netflow-v9", "10.0.0.1", 100L, tmpl);

        TemplateRecord result = cache.get("netflow-v9", "10.0.0.1", 100L, 256);

        assertThat(result).isNotNull();
        assertThat(result.templateId()).isEqualTo(256);
        assertThat(result.fields()).hasSize(2);
    }

    // Test happy path: missing NetFlow v9 template lookup returns null.
    @Test
    @DisplayName("get for missing key → returns null")
    void get_missingTemplate_returnsNull() {
        TemplateRecord result = cache.get("netflow-v9", "10.0.0.1", 100L, 256);

        assertThat(result).isNull();
    }

    // Test happy path: same NetFlow v9 template key replaces the previous template.
    @Test
    @DisplayName("put with same key → replaces existing template")
    void put_replacesExistingTemplate() {
        TemplateRecord first = sampleTemplate(256);
        TemplateRecord second = new TemplateRecord(256,
                List.of(TemplateField.standard(7, 2)), false);

        cache.put("netflow-v9", "10.0.0.1", 100L, first);
        cache.put("netflow-v9", "10.0.0.1", 100L, second);

        TemplateRecord result = cache.get("netflow-v9", "10.0.0.1", 100L, 256);
        assertThat(result).isNotNull();
        assertThat(result.fields()).hasSize(1);
    }

    // Test happy path: removing a NetFlow v9 template deletes it from the cache.
    @Test
    @DisplayName("remove → subsequent get returns null")
    void remove_deletesTemplate() {
        cache.put("netflow-v9", "10.0.0.1", 100L, sampleTemplate(256));
        cache.remove("netflow-v9", "10.0.0.1", 100L, 256);

        assertThat(cache.get("netflow-v9", "10.0.0.1", 100L, 256)).isNull();
    }

    // Test happy path: exporter keys keep NetFlow v9 templates separate.
    @Test
    @DisplayName("Different exporter keys → separate templates")
    void differentExporterKeys_separateTemplates() {
        TemplateRecord tmplA = sampleTemplate(256);
        TemplateRecord tmplB = new TemplateRecord(256,
                List.of(TemplateField.standard(1, 4)), false);

        cache.put("netflow-v9", "10.0.0.1", 100L, tmplA);
        cache.put("netflow-v9", "10.0.0.2", 100L, tmplB);

        assertThat(cache.get("netflow-v9", "10.0.0.1", 100L, 256).fields()).hasSize(2);
        assertThat(cache.get("netflow-v9", "10.0.0.2", 100L, 256).fields()).hasSize(1);
    }

    // Test happy path: source/domain IDs keep NetFlow v9 templates separate.
    @Test
    @DisplayName("Different domain IDs → separate templates")
    void differentDomainIds_separateTemplates() {
        TemplateRecord tmplA = sampleTemplate(256);
        TemplateRecord tmplB = new TemplateRecord(256,
                List.of(TemplateField.standard(1, 4)), false);

        cache.put("netflow-v9", "10.0.0.1", 100L, tmplA);
        cache.put("netflow-v9", "10.0.0.1", 200L, tmplB);

        assertThat(cache.get("netflow-v9", "10.0.0.1", 100L, 256).fields()).hasSize(2);
        assertThat(cache.get("netflow-v9", "10.0.0.1", 200L, 256).fields()).hasSize(1);
    }
}
