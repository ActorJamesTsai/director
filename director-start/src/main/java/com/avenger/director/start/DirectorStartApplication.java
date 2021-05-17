package com.avenger.director.start;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties
@SpringBootApplication
public class DirectorStartApplication {

    public static void main(String[] args) {
        SpringApplication.run(DirectorStartApplication.class, args);
    }

}
