package com.kien.networkflowcollector.collectors.netflow.template;

public record TemplateKey(String protocol, String exporterKey, long domainId, int templateId) {}
