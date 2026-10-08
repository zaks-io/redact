use crate::Span;
use serde::Deserialize;
use std::fmt;

/// Static descriptions of detector evidence, never credential validity or claims.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    AuthHeader,
    PrivateKey,
    UrlCredentials,
    ConnectionString,
    JoseFormat,
    CredentialContainer,
    KubernetesSecret,
    SensitiveFieldOrQuotedCredential,
    GithubTokenFormat,
    GitlabAccessTokenFormat,
    GitlabTokenFormat,
    NpmTokenFormat,
    PypiTokenFormat,
    HuggingfaceTokenFormat,
    OpenaiKeyFormat,
    GenericSecretKeyFormat,
    AnthropicKeyFormat,
    StripeKeyFormat,
    StripeWebhookFormat,
    SlackTokenFormat,
    SlackRotationFormat,
    VaultTokenFormat,
    OnepasswordServiceFormat,
    VercelTokenFormat,
    LinearTokenFormat,
    NotionTokenFormat,
    DigitaloceanTokenFormat,
    PulumiTokenFormat,
    GrafanaTokenFormat,
    NewrelicKeyFormat,
    CloudflareTokenFormat,
    SupabaseSecretFormat,
    AwsAccessIdFormat,
    SendgridKeyFormat,
    BcryptVerifierFormat,
    PhcVerifierFormat,
}

impl Evidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::AuthHeader => "authorization header",
            Self::PrivateKey => "private-key block",
            Self::UrlCredentials => "URL credential",
            Self::ConnectionString => "connection-string credential",
            Self::JoseFormat => "JOSE token format",
            Self::CredentialContainer => "credential container",
            Self::KubernetesSecret => "Kubernetes Secret document",
            Self::SensitiveFieldOrQuotedCredential => "sensitive field or quoted credential",
            Self::GithubTokenFormat => "GitHub token format",
            Self::GitlabAccessTokenFormat => "GitLab access-token format",
            Self::GitlabTokenFormat => "GitLab token format",
            Self::NpmTokenFormat => "npm token format",
            Self::PypiTokenFormat => "PyPI token format",
            Self::HuggingfaceTokenFormat => "Hugging Face token format",
            Self::OpenaiKeyFormat => "OpenAI key format",
            Self::GenericSecretKeyFormat => "generic secret-key format; provider unknown",
            Self::AnthropicKeyFormat => "Anthropic key format",
            Self::StripeKeyFormat => "Stripe secret or restricted-key format",
            Self::StripeWebhookFormat => "Stripe webhook-secret format",
            Self::SlackTokenFormat => "Slack token format",
            Self::SlackRotationFormat => "Slack rotation-token format",
            Self::VaultTokenFormat => "Vault token format",
            Self::OnepasswordServiceFormat => "1Password service-account token format",
            Self::VercelTokenFormat => "Vercel token format",
            Self::LinearTokenFormat => "Linear token format",
            Self::NotionTokenFormat => "Notion token format",
            Self::DigitaloceanTokenFormat => "DigitalOcean token format",
            Self::PulumiTokenFormat => "Pulumi token format",
            Self::GrafanaTokenFormat => "Grafana token format",
            Self::NewrelicKeyFormat => "New Relic key format",
            Self::CloudflareTokenFormat => "Cloudflare token format",
            Self::SupabaseSecretFormat => "Supabase secret-key format",
            Self::AwsAccessIdFormat => {
                "AWS access-key ID format; separate secret key not identified"
            }
            Self::SendgridKeyFormat => "SendGrid key format",
            Self::BcryptVerifierFormat => "bcrypt password-verifier format",
            Self::PhcVerifierFormat => "PHC password-verifier format",
        }
    }

    pub(crate) fn provider_rule_id(self) -> Option<&'static str> {
        Some(match self {
            Self::GithubTokenFormat => "github-access",
            Self::GitlabAccessTokenFormat => "gitlab-access",
            Self::GitlabTokenFormat => "gitlab-other",
            Self::NpmTokenFormat => "npm-token",
            Self::PypiTokenFormat => "pypi-token",
            Self::HuggingfaceTokenFormat => "huggingface-token",
            Self::OpenaiKeyFormat => "openai-key",
            Self::GenericSecretKeyFormat => "generic-secret-key",
            Self::AnthropicKeyFormat => "anthropic-key",
            Self::StripeKeyFormat => "stripe-key",
            Self::StripeWebhookFormat => "stripe-webhook",
            Self::SlackTokenFormat => "slack-token",
            Self::SlackRotationFormat => "slack-rotation",
            Self::VaultTokenFormat => "vault-token",
            Self::OnepasswordServiceFormat => "onepassword-service",
            Self::VercelTokenFormat => "vercel-token",
            Self::LinearTokenFormat => "linear-token",
            Self::NotionTokenFormat => "notion-token",
            Self::DigitaloceanTokenFormat => "digitalocean-token",
            Self::PulumiTokenFormat => "pulumi-token",
            Self::GrafanaTokenFormat => "grafana-token",
            Self::NewrelicKeyFormat => "newrelic-key",
            Self::CloudflareTokenFormat => "cloudflare-current",
            Self::SupabaseSecretFormat => "supabase-current",
            Self::AwsAccessIdFormat => "aws-access-id",
            Self::SendgridKeyFormat => "sendgrid-key",
            Self::BcryptVerifierFormat => "bcrypt-verifier",
            Self::PhcVerifierFormat => "phc-verifier",
            _ => return None,
        })
    }
}

pub(crate) struct Finding {
    pub span: Span,
    pub label: Evidence,
}

/// Approved metadata about one merged redaction, without input fragments or lengths.
#[derive(Debug, PartialEq, Eq)]
pub struct Redaction {
    pub fingerprint: String,
    pub line: usize,
    pub labels: Vec<Evidence>,
}

pub struct Filtered {
    pub output: String,
    pub redactions: Vec<Redaction>,
}

impl fmt::Debug for Filtered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Filtered")
            .field("output", &"[opaque]")
            .field("redactions", &self.redactions)
            .finish()
    }
}
