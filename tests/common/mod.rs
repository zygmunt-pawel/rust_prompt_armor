//! Test helpers shared between integration tests.
//!
//! For the `llm-tests` feature, this module documents how to plug in a real
//! LLM client. The crate intentionally does NOT depend on any HTTP/SDK crate
//! — the caller of the attack suite supplies their own client implementation.
//!
//! ## Example: Anthropic API via bare reqwest
//!
//! ```ignore
//! use anyhow::Result;
//! use rust_prompt_armor::llm::LlmClient;
//!
//! pub struct AnthropicClient {
//!     api_key: String,
//!     model: String,
//! }
//!
//! #[async_trait::async_trait]
//! impl LlmClient for AnthropicClient {
//!     async fn complete(&self, system: &str, user: &str) -> Result<String> {
//!         let body = serde_json::json!({
//!             "model": self.model,
//!             "max_tokens": 256,
//!             "system": system,
//!             "messages": [{"role": "user", "content": user}],
//!         });
//!         let resp = reqwest::Client::new()
//!             .post("https://api.anthropic.com/v1/messages")
//!             .header("x-api-key", &self.api_key)
//!             .header("anthropic-version", "2023-06-01")
//!             .header("content-type", "application/json")
//!             .json(&body)
//!             .send().await?
//!             .error_for_status()?
//!             .json::<serde_json::Value>().await?;
//!         Ok(resp["content"][0]["text"].as_str().unwrap_or("").to_string())
//!     }
//! }
//! ```
//!
//! The attack suite at `tests/llm_attack_suite.rs` expects an env var
//! `ANTHROPIC_API_KEY` and instantiates the above (or equivalent) client.

#![allow(dead_code)]
