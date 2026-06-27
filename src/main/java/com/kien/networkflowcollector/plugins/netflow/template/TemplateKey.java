package com.kien.networkflowcollector.plugins.netflow.template;

public record TemplateKey(String protocol, String exporterKey, long domainId, int templateId) {}
