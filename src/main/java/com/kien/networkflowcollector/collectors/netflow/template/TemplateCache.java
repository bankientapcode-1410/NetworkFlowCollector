package com.kien.networkflowcollector.collectors.netflow.template;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class TemplateCache {

    private final Map<TemplateKey, TemplateRecord> templates = new ConcurrentHashMap<>();

    public void put(String protocol, String exporterKey, long domainId, TemplateRecord template) {
        templates.put(new TemplateKey(protocol, exporterKey, domainId, template.templateId()), template);
    }

    public TemplateRecord get(String protocol, String exporterKey, long domainId, int templateId) {
        return templates.get(new TemplateKey(protocol, exporterKey, domainId, templateId));
    }

    public void remove(String protocol, String exporterKey, long domainId, int templateId) {
        templates.remove(new TemplateKey(protocol, exporterKey, domainId, templateId));
    }
}
