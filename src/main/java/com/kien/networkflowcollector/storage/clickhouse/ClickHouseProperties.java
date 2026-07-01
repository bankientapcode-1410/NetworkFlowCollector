package com.kien.networkflowcollector.storage.clickhouse;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "clickhouse")
public class ClickHouseProperties {

    private boolean enabled = true;
    private String url = "jdbc:clickhouse://localhost:8123/default";
    private String user = "kien";
    private String password = "2606";
}
