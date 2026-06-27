package com.kien.networkflowcollector.plugins.netflow.template;

public record TemplateField(
        int type, int length, boolean enterpriseSpecific, long enterpriseNumber, boolean scope) {

    public static final int VARIABLE_LENGTH = 0xffff;

    public TemplateField {
        if (type < 0) {
            throw new IllegalArgumentException("template field type must be non-negative");
        }
        if (length < 0 || length > VARIABLE_LENGTH) {
            throw new IllegalArgumentException("template field length out of range: " + length);
        }
    }

    public static TemplateField standard(int type, int length) {
        return new TemplateField(type, length, false, 0, false);
    }

    public TemplateField asScope() {
        return new TemplateField(type, length, enterpriseSpecific, enterpriseNumber, true);
    }

    public boolean variableLength() {
        return length == VARIABLE_LENGTH;
    }
}
