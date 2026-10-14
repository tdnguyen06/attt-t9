package com.example.backend.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        File[] possibleEnvFiles = new File[]{
                new File(".env"),
                new File("../.env"),
                new File("backend/.env"),
                new File(System.getProperty("user.dir"), ".env"),
                new File(System.getProperty("user.dir"), "backend/.env")
        };

        for (File envFile : possibleEnvFiles) {
            if (envFile.exists() && envFile.isFile()) {
                Map<String, Object> envMap = new HashMap<>();
                try (BufferedReader reader = new BufferedReader(new FileReader(envFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) {
                            continue;
                        }
                        int idx = line.indexOf('=');
                        String key = line.substring(0, idx).trim();
                        String value = line.substring(idx + 1).trim();
                        if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
                            value = value.substring(1, value.length() - 1);
                        }
                        envMap.put(key, value);
                    }
                    if (!envMap.isEmpty()) {
                        environment.getPropertySources().addFirst(new MapPropertySource("dotenvProperties", envMap));
                    }
                    break;
                } catch (Exception ignored) {
                }
            }
        }
    }
}
