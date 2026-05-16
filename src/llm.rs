//! `LlmClient` trait for the optional `llm-tests` feature.
//!
//! Callers implement this trait against their preferred SDK
//! (anthropic-sdk, openai, bare reqwest, ...) so the attack suite in
//! `tests/llm_attack_suite.rs` can run against real models without
//! the crate itself depending on any HTTP/SDK crate.

#[async_trait::async_trait]
pub trait LlmClient: Send + Sync {
    /// Send a (system, user) pair to the model. Return the assistant text
    /// (no need to parse JSON / tool calls — the attack suite checks for
    /// presence of leak markers in plain text).
    async fn complete(&self, system: &str, user: &str) -> anyhow::Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoClient;
    #[async_trait::async_trait]
    impl LlmClient for EchoClient {
        async fn complete(&self, _system: &str, user: &str) -> anyhow::Result<String> {
            Ok(format!("echo: {user}"))
        }
    }

    #[tokio::test]
    async fn trait_can_be_implemented_and_called() {
        let client: &dyn LlmClient = &EchoClient;
        let response = client.complete("sys", "hello").await.unwrap();
        assert_eq!(response, "echo: hello");
    }
}
