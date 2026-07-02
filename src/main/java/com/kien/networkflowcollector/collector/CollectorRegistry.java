package com.kien.networkflowcollector.collector;

import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowPublisher;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.SmartLifecycle;

public class CollectorRegistry implements SmartLifecycle {

    private static final Logger LOGGER = LoggerFactory.getLogger(CollectorRegistry.class);

    private final CollectorProperties properties;
    private final ObjectProvider<FlowPublisher> publisherProvider;
    private final Map<String, FlowCollector> collectorsByType;
    private final AtomicBoolean running = new AtomicBoolean();
    private final List<FlowCollector> startedCollectors = new ArrayList<>();

    public CollectorRegistry(CollectorProperties properties, ObjectProvider<FlowPublisher> publisherProvider) {
        this(properties, publisherProvider, loadFromServiceLoader());
    }

    CollectorRegistry(
            CollectorProperties properties,
            ObjectProvider<FlowPublisher> publisherProvider,
            Collection<FlowCollector> collectors) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.publisherProvider = Objects.requireNonNull(publisherProvider, "publisherProvider");
        this.collectorsByType = indexCollectors(collectors);
    }

    public Collection<FlowCollector> collectors() {
        return collectorsByType.values();
    }

    @Override
    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        startedCollectors.clear();
        for (FlowCollector collector : collectorsByType.values()) {
            startCollector(collector);
        }
    }

    @Override
    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        for (int i = startedCollectors.size() - 1; i >= 0; i--) {
            stopCollector(startedCollectors.get(i));
        }
        startedCollectors.clear();
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    @Override
    public int getPhase() {
        return Integer.MAX_VALUE - 50;
    }

    private FlowPublisher requiredPublisher(FlowCollector collector) {
        FlowPublisher publisher = publisherProvider.getIfAvailable();
        if (publisher == null) {
            throw new CollectorRegistryException(
                    "Collector "
                            + collector.type()
                            + " is enabled but no FlowPublisher bean is available");
        }
        return publisher;
    }

    private void startCollector(FlowCollector collector) {
        String collectorType = collector.type();
        try {
            CollectorConfig config = properties.configFor(collectorType);
            FlowPublisher publisher =
                    config.enabled() ? requiredPublisher(collector) : publisherProvider.getIfAvailable();
            collector.init(config, publisher);
            if (config.enabled()) {
                collector.start();
                startedCollectors.add(collector);
            }
        } catch (RuntimeException e) {
            LOGGER.error("Collector {} failed during init/start and will remain down", collectorType, e);
        }
    }

    private void stopCollector(FlowCollector collector) {
        try {
            collector.stop();
        } catch (RuntimeException e) {
            LOGGER.error("Collector {} failed during stop", collector.type(), e);
        }
    }

    private static Collection<FlowCollector> loadFromServiceLoader() {
        return ServiceLoader.load(FlowCollector.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
    }

    private static Map<String, FlowCollector> indexCollectors(Collection<FlowCollector> collectors) {
        Map<String, FlowCollector> indexed = new LinkedHashMap<>();
        for (FlowCollector collector : collectors) {
            String type = collector.type();
            if (type == null || type.isBlank()) {
                throw new CollectorRegistryException(
                        "Collector " + collector.getClass().getName() + " returned a blank type");
            }
            FlowCollector previous = indexed.putIfAbsent(type, collector);
            if (previous != null) {
                throw new CollectorRegistryException(
                        "Duplicate collector type "
                                + type
                                + ": "
                                + previous.getClass().getName()
                                + " and "
                                + collector.getClass().getName());
            }
        }
        return Map.copyOf(indexed);
    }
}
