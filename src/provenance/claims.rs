use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorRef {
    pub key_id: String,
    pub display_name: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureClaim {
    pub actor: ActorRef,
    pub captured_at: chrono::DateTime<chrono::Utc>,
    pub device_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipClaim {
    pub author: ActorRef,
    pub statement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditClaim {
    pub editor: ActorRef,
    pub edit_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationClaim {
    pub publisher: ActorRef,
    pub publication_url: Option<String>,
}
