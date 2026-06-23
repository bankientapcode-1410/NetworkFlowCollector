package com.kien.networkflowcollector.spi;

import java.util.concurrent.CompletionStage;

public interface FlowPublisher {

    CompletionStage<Void> publish(RawFlowRecord record);
}
