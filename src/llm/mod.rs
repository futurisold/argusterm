use std::sync::Arc;
use std::time::Duration;

use minijinja::Environment;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};

use crate::state::CveEntry;
use crate::tui::{AppEvent, LlmUpdate};



fn load_templates() -> Environment<'static> {
    let mut env = Environment::new();
    env.add_template("triage_system", include_str!("../../prompts/triage_system.j2"))
        .expect("failed to load triage_system.j2");
    env.add_template("triage_user", include_str!("../../prompts/triage_user.j2"))
        .expect("failed to load triage_user.j2");
    env
}

#[derive(Deserialize)]
struct ApiResponse { content: Vec<ContentBlock> }

#[derive(Deserialize)]
struct ContentBlock { text: Option<String> }

#[derive(Deserialize)]
struct TriageResult {
    content_type: String,
    relevance_score: f32,
    severity: String,
    summary: String,
    dot_diagram: String,
    cve_ids: Vec<String>,
}

fn triage_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "content_type": {
                "type": "string",
                "enum": ["cve", "advisory", "news", "research", "promotional", "irrelevant"],
                "description": "Classification of the entry content"
            },
            "relevance_score": {
                "type": "number",
                "description": "How relevant to AI/ML/LLM security, 0.0 to 1.0"
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "unknown"],
                "description": "CVSS severity if stated, otherwise inferred from impact"
            },
            "summary": {
                "type": "string",
                "description": "2-3 sentence vulnerability analysis"
            },
            "dot_diagram": {
                "type": "string",
                "description": "Graphviz DOT digraph showing the attack surface. Use rankdir=TB, short labels, box shapes."
            },
            "cve_ids": {
                "type": "array",
                "items": { "type": "string" },
                "description": "CVE identifiers (CVE-YYYY-NNNNN) mentioned. Empty array if none."
            }
        },
        "required": ["content_type", "relevance_score", "severity", "summary", "dot_diagram", "cve_ids"],
        "additionalProperties": false
    })
}

async fn scrape_url(client: &reqwest::Client, api_key: &str, url: &str) -> anyhow::Result<String> {
    let resp = client
        .post("https://api.parallel.ai/v1beta/extract")
        .header("x-api-key", api_key)
        .json(&json!({
            "urls": [url],
            "objective": "Extract the full text of this security advisory, vulnerability report, or cybersecurity news article. Include any CVE numbers, affected products, and technical details.",
            "full_content": true,
        }))
        .send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Parallel.ai {}", resp.status());
    }
    let body: Value = resp.json().await?;
    body["results"].get(0)
        .and_then(|r| r["full_content"].as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no content from Parallel.ai"))
}

async fn render_dot(dot: &str, graph_easy_bin: &str, perl5lib: &str) -> anyhow::Result<String> {
    let mut child = tokio::process::Command::new(graph_easy_bin)
        .args(["--from=dot", "--as=ascii"]).env("PERL5LIB", perl5lib)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(dot.as_bytes()).await?;
    }
    let output = child.wait_with_output().await?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        anyhow::bail!("graph-easy: {}", String::from_utf8_lossy(&output.stderr))
    }
}

async fn call_anthropic(
    client: &reqwest::Client, api_key: &str, model: &str,
    env: &Environment<'_>, entry: &CveEntry, content: &str,
) -> anyhow::Result<TriageResult> {
    let system_prompt = env.get_template("triage_system").expect("missing triage_system")
        .render(minijinja::context!()).expect("failed to render triage_system");
    // NOTE: truncate to ~6000 chars, safe for multi-byte UTF-8
    let desc: String = content.chars().take(6000).collect();
    let user_msg = env.get_template("triage_user").expect("missing triage_user")
        .render(minijinja::context! {
            entry_id => &entry.id, entry_title => &entry.title, entry_content => &desc,
        }).expect("failed to render triage_user");

    let body = json!({
        "model": model, "max_tokens": 1024, "system": system_prompt,
        "messages": [{"role": "user", "content": user_msg}],
        "output_config": {"format": {"type": "json_schema", "schema": triage_schema()}},
    });
    let resp = client.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("API {}: {}", resp.status(), resp.text().await?);
    }
    let api: ApiResponse = resp.json().await?;
    let text = api.content.first().and_then(|b| b.text.as_deref()).unwrap_or("{}");
    Ok(serde_json::from_str(text)?)
}

#[allow(clippy::too_many_arguments)]
async fn triage_one(
    client: &reqwest::Client, api_key: &str, model: &str,
    env: &Environment<'_>, entry: &CveEntry, scraper_key: Option<&str>,
    graph_easy_bin: &str, perl5lib: &str,
) -> anyhow::Result<(TriageResult, String, Option<String>)> {
    let scraped = match (entry.url.as_deref(), scraper_key) {
        _ if entry.scraped_content.is_some() => entry.scraped_content.clone(),
        (Some(url), Some(key)) => scrape_url(client, key, url).await.ok(),
        _ => None,
    };
    let content = scraped.as_deref().unwrap_or(&entry.description);
    let result = call_anthropic(client, api_key, model, env, entry, content).await?;
    let diagram = render_dot(&result.dot_diagram, graph_easy_bin, perl5lib).await
        .unwrap_or_else(|e| format!("(diagram render failed: {e})"));
    Ok((result, diagram, scraped))
}

#[allow(clippy::too_many_arguments)]
async fn triage_loop(
    tx: mpsc::UnboundedSender<AppEvent>, rx: mpsc::UnboundedReceiver<CveEntry>,
    model: Arc<str>, api_key: Arc<str>, scraper_key: Option<Arc<str>>,
    graph_easy_bin: Arc<str>, perl5lib: Arc<str>, semaphore: Arc<Semaphore>,
) {
    let client = Arc::new(reqwest::Client::builder()
        .timeout(Duration::from_secs(60)).build().expect("failed to build HTTP client"));
    let env = Arc::new(load_templates());
    let mut rx = rx;

    while let Some(entry) = rx.recv().await {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let (client, api_key, model, scraper_key, tx, env, ge_bin, pe_lib) = (
            client.clone(), api_key.clone(), model.clone(),
            scraper_key.clone(), tx.clone(), env.clone(),
            graph_easy_bin.clone(), perl5lib.clone(),
        );
        tokio::spawn(async move {
            let evt = match triage_one(&client, &api_key, &model, &env, &entry, scraper_key.as_deref(), &ge_bin, &pe_lib).await {
                Ok((r, diagram, scraped)) => AppEvent::LlmResult(LlmUpdate {
                    entry_id: entry.id.clone(), content_type: r.content_type,
                    severity: r.severity, summary: r.summary, ascii_diagram: diagram,
                    relevance_score: r.relevance_score, cve_ids: r.cve_ids, scraped_content: scraped,
                }),
                Err(_) => AppEvent::Error,
            };
            let _ = tx.send(evt);
            drop(permit);
        });
    }
}

pub fn spawn(
    event_tx: mpsc::UnboundedSender<AppEvent>, model: String, api_key: String,
    scraper_key: Option<String>, max_concurrent: usize,
    graph_easy_bin: String, perl5lib: String,
) -> mpsc::UnboundedSender<CveEntry> {
    let (entry_tx, entry_rx) = mpsc::unbounded_channel();
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    tokio::spawn(triage_loop(
        event_tx, entry_rx, model.into(), api_key.into(),
        scraper_key.map(|s| Arc::from(s.as_str())),
        Arc::from(graph_easy_bin.as_str()), Arc::from(perl5lib.as_str()), semaphore,
    ));
    entry_tx
}
