# Contributing

## Adding A Collector

1. Create a new package under `src/main/java/com/kien/networkflowcollector/collectors/<format>`.
2. Implement `FlowCollector` and declare every emitted `sourceType`.
3. Add one `FlowNormalizer` for each source type.
4. Register implementations with Java SPI under `src/main/resources/META-INF/services` when discovery is needed.
5. Add fixture-based parser and normalizer tests.
6. Update sample configuration and OpenAPI documentation when endpoints change.
7. Run the full Maven build before integration.
