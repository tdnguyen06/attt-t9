package com.example.backend.modules.llm;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@Slf4j
public class LlmProperties {

    // 1. Primary: DeepSeek AI
    @Value("${deepseek.api.key:${DEEPSEEK_API_KEY:}}")
    private String deepseekApiKey;

    @Value("${deepseek.api.url:${DEEPSEEK_API_URL:https://api.deepseek.com/chat/completions}}")
    private String deepseekApiUrl;

    @Value("${deepseek.model:${DEEPSEEK_MODEL:deepseek-chat}}")
    private String deepseekModel;

    // 2. Fallback: Google Gemini Pro
    @Value("${gemini.api.key:${GEMINI_API_KEY:}}")
    private String geminiApiKey;

    @Value("${gemini.api.url:${GEMINI_API_URL:https://generativelanguage.googleapis.com/v1beta/models}}")
    private String geminiApiUrl;

    @Value("${gemini.model:${GEMINI_MODEL:gemini-3.5-flash}}")
    private String geminiModel;

    @Value("${llm.timeout-seconds:30}")
    private int timeoutSeconds;

    public String getDeepseekApiKey() {
        String envKey = readFromEnvFile("DEEPSEEK_API_KEY");
        if (envKey != null && !envKey.isBlank()) return envKey.trim();
        return deepseekApiKey != null && !deepseekApiKey.isBlank() && !deepseekApiKey.startsWith("your-") ? deepseekApiKey.trim() : "";
    }

    public String getDeepseekApiUrl() {
        String envUrl = readFromEnvFile("DEEPSEEK_API_URL");
        if (envUrl != null && !envUrl.isBlank()) return envUrl.trim();
        return deepseekApiUrl != null && !deepseekApiUrl.isBlank() ? deepseekApiUrl.trim() : "https://api.deepseek.com/chat/completions";
    }

    public String getDeepseekModel() {
        String envModel = readFromEnvFile("DEEPSEEK_MODEL");
        if (envModel != null && !envModel.isBlank()) return cleanModelName(envModel.trim());
        return cleanModelName(deepseekModel != null && !deepseekModel.isBlank() ? deepseekModel : "deepseek-chat");
    }

    public String getGeminiApiKey() {
        String envKey = readFromEnvFile("GEMINI_API_KEY");
        if (envKey != null && !envKey.isBlank()) return envKey.trim();
        return geminiApiKey != null && !geminiApiKey.isBlank() && !geminiApiKey.startsWith("your-") ? geminiApiKey.trim() : "";
    }

    public String getGeminiApiUrl() {
        String envUrl = readFromEnvFile("GEMINI_API_URL");
        if (envUrl != null && !envUrl.isBlank()) return envUrl.trim();
        return geminiApiUrl != null && !geminiApiUrl.isBlank() ? geminiApiUrl.trim() : "https://generativelanguage.googleapis.com/v1beta/models";
    }

    public String getGeminiModel() {
        String envModel = readFromEnvFile("GEMINI_MODEL");
        if (envModel != null && !envModel.isBlank()) return cleanModelName(envModel.trim());
        String current = geminiModel != null && !geminiModel.isBlank() ? geminiModel : "gemini-3.5-flash";
        return cleanModelName(current);
    }

    public boolean isConfigured() {
        return !getDeepseekApiKey().isBlank() || !getGeminiApiKey().isBlank();
    }

    public String getModel() {
        if (!getDeepseekApiKey().isBlank()) {
            return getDeepseekModel();
        }
        if (!getGeminiApiKey().isBlank()) {
            return getGeminiModel();
        }
        return getDeepseekModel();
    }

    private String cleanModelName(String modelName) {
        if (modelName == null || modelName.isBlank()) return "deepseek-chat";
        String clean = modelName.replaceAll("[`'\"\\s]+", "").trim();
        return clean.isBlank() ? "deepseek-chat" : clean;
    }

    private String readFromEnvFile(String varName) {
        String[] paths = new String[]{".env", "../.env", "backend/.env", "d:/ATTT---T9/backend/.env", "d:/ATTT---T9/.env"};
        for (String p : paths) {
            java.io.File f = new java.io.File(p);
            if (f.exists() && f.isFile()) {
                try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("#")) continue;
                        if (line.startsWith(varName + "=")) {
                            String val = line.substring((varName + "=").length()).trim();
                            if (val.contains("#")) {
                                val = val.substring(0, val.indexOf('#')).trim();
                            }
                            val = val.replaceAll("^[`'\"\\s]+", "").replaceAll("[`'\"\\s]+$", "");
                            if (!val.isEmpty()) {
                                return val;
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        return "";
    }
}
