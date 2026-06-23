package com.kien.networkflowcollector.spi;

import java.util.Set;

public interface FlowCollector {

    String type();

    Set<String> supportedSourceTypes();

    void init(CollectorConfig config, FlowPublisher publisher);

    void start();

    void stop();

    CollectorHealth health();
}
