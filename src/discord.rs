use std::{env, time::Duration};

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::errors::BackendError;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Channel {
    id: String,
}

const DISCORD_BASE_URL: &str = "https://discord.com/api";
#[derive(Clone)]
pub struct DiscordClient(Client);
impl DiscordClient {
    pub fn new() -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::with_capacity(1);
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&{
                let token = env::var("DISCORD_TOKEN").expect("DISCORD_TOKEN must be set");
                format!("Bot {}", token)
            })
            .unwrap(),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self(client))
    }
    pub async fn send_msg(&self, user_id: String, content: String) -> Result<(), BackendError> {
        let dm_channel = self
            .0
            .post(format!("{}/users/@me/channels", DISCORD_BASE_URL))
            .json(&json!({
                "recipient_id": user_id
            }))
            .send()
            .await?
            .json::<Channel>()
            .await?;
        println!("DM Channel: {:?}", dm_channel);
        let send_rsp = self
            .0
            .post(format!(
                "{}/channels/{}/messages",
                DISCORD_BASE_URL, dm_channel.id
            ))
            .json(&json!({
                "content": content
            }))
            .send()
            .await?;
        let resp = send_rsp.text().await?;
        println!("{:?}", resp);
        Ok(())
    }
}
