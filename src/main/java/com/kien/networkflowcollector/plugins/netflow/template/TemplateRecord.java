package com.kien.networkflowcollector.plugins.netflow.template;

import java.util.List;

public record TemplateRecord(int templateId, List<TemplateField> fields, boolean optionsTemplate) {

    public TemplateRecord {
        if (templateId < 0) {
            throw new IllegalArgumentException("template id must be non-negative");
        }
        fields = List.copyOf(fields);
    }

    public int fixedRecordLength() {
        int total = 0;
        for (TemplateField field : fields) {
            if (field.variableLength()) {
                return -1;
            }
            total += field.length();
        }
        return total;
    }
}
