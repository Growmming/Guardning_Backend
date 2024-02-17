package com.growmming.gurdening;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class GurdeningApplication {

    public static void main(String[] args) {
        SpringApplication.run(GurdeningApplication.class, args);
    }

}
