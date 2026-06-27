package com.kien.networkflowcollector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.kien.networkflowcollector")
public class NetworkFlowCollectorApplication {

    public static void main(String[] args) {
        SpringApplication.run(NetworkFlowCollectorApplication.class, args);
    }

}
