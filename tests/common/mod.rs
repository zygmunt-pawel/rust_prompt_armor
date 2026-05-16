//! Test helpers shared between integration tests.
//!
//! Includes an example `LlmClient` impl backed by OpenRouter
//! (https://openrouter.ai) — a single API that routes to many models
//! (OpenAI, Anthropic, Google, Meta, ...). Behind the `llm-tests`
//! feature; reads `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL`
//! (default: `openai/gpt-4o-mini`) from env.
//!
//! Swap in any other provider by writing your own `LlmClient` impl —
//! the trait is intentionally minimal: one async `complete(system, user)`
//! method returning the assistant text.

#![allow(dead_code)]

#[cfg(feature = "llm-tests")]
pub mod openrouter {
    use anyhow::{Context, Result, anyhow};
    use rust_prompt_armor::llm::LlmClient;

    // Default to gpt-4o-mini: cheap, fast, no reasoning tokens. Reasoning
    // models (gpt-5-*) need a much larger max_tokens because the budget
    // is consumed by reasoning before any visible content is emitted.
    const DEFAULT_MODEL: &str = "openai/gpt-4o-mini";
    const ENDPOINT: &str = "https://openrouter.ai/api/v1/chat/completions";

    pub struct OpenRouterClient {
        api_key: String,
        model: String,
        http: reqwest::Client,
    }

    impl OpenRouterClient {
        /// Build from environment. Requires `OPENROUTER_API_KEY`.
        /// Model is `OPENROUTER_MODEL` if set, else `openai/gpt-5-mini`.
        pub fn from_env() -> Result<Self> {
            let api_key = std::env::var("OPENROUTER_API_KEY")
                .context("OPENROUTER_API_KEY not set; the llm-tests suite needs a key")?;
            let model =
                std::env::var("OPENROUTER_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
            // Modest read timeout — OpenRouter occasionally adds latency
            // when routing to slower upstreams.
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?;
            Ok(Self {
                api_key,
                model,
                http,
            })
        }
    }

    #[async_trait::async_trait]
    impl LlmClient for OpenRouterClient {
        async fn complete(&self, system: &str, user: &str) -> Result<String> {
            let body = serde_json::json!({
                "model": self.model,
                // GPT-5 family allocates tokens to reasoning before content;
                // 256 leaves headroom for both. Tests only check substring
                // presence so we don't need long outputs.
                "max_tokens": 256,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            });

            let resp = self
                .http
                .post(ENDPOINT)
                .bearer_auth(&self.api_key)
                // OpenRouter recommends a Referer + Title for analytics; not
                // required, but polite.
                .header(
                    "HTTP-Referer",
                    "https://github.com/zygmunt-pawel/rust_prompt_armor",
                )
                .header("X-Title", "rust_prompt_armor llm-tests")
                .json(&body)
                .send()
                .await
                .context("OpenRouter request failed")?;

            let status = resp.status();
            let raw = resp
                .text()
                .await
                .context("reading OpenRouter response body")?;
            if !status.is_success() {
                return Err(anyhow!("OpenRouter HTTP {status}: {raw}"));
            }

            let value: serde_json::Value =
                serde_json::from_str(&raw).context("parsing OpenRouter JSON response")?;

            // Standard OpenAI-compatible shape:
            // { "choices": [{ "message": { "content": "..." } }, ...] }
            value
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    anyhow!("OpenRouter response missing choices[0].message.content: {raw}")
                })
        }
    }
}
