use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::state::{CveEntry, FeedSource};

pub struct Db { conn: Connection }

impl Db {
    pub fn open() -> anyhow::Result<Self> {
        std::fs::create_dir_all(".argusterm")?;
        let conn = Connection::open(".argusterm/cache.db")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'unknown', published TEXT NOT NULL,
                source TEXT NOT NULL, url TEXT, llm_summary TEXT, ascii_diagram TEXT,
                relevance_score REAL)",
        )?;
        for col in ["scraped_content TEXT", "cve_ids TEXT DEFAULT '[]'", "content_type TEXT"] {
            let _ = conn.execute(&format!("ALTER TABLE entries ADD COLUMN {col}"), []);
        }
        Ok(Self { conn })
    }

    pub fn load_since(&self, days: u64) -> anyhow::Result<Vec<CveEntry>> {
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, title, description, severity, published, source,
                    url, llm_summary, ascii_diagram, relevance_score,
                    scraped_content, cve_ids, content_type
             FROM entries WHERE published >= ?1 ORDER BY published DESC",
        )?;
        let rows = stmt.query_map(params![cutoff], |row| {
            let sev: String = row.get::<_, String>(3).unwrap_or_default();
            let cve_raw: String = row.get::<_, String>(11).unwrap_or_else(|_| "[]".into());
            Ok(CveEntry {
                id: row.get(0)?, title: row.get(1)?, description: row.get(2)?,
                severity: if sev.is_empty() || sev == "unknown" { None } else { Some(sev) },
                published: row.get::<_, String>(4)?.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now()),
                source: parse_source(&row.get::<_, String>(5)?),
                url: row.get(6)?, llm_summary: row.get(7)?, ascii_diagram: row.get(8)?,
                relevance_score: row.get(9)?, scraped_content: row.get(10)?,
                cve_ids: serde_json::from_str(&cve_raw).unwrap_or_default(),
                content_type: row.get(12)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn upsert_entry(&self, e: &CveEntry) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO entries (id, title, description, severity, published, source, url,
                                  llm_summary, ascii_diagram, relevance_score,
                                  scraped_content, cve_ids, content_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
                title=excluded.title, description=excluded.description, severity=excluded.severity,
                published=excluded.published, source=excluded.source, url=excluded.url,
                llm_summary=excluded.llm_summary, ascii_diagram=excluded.ascii_diagram,
                relevance_score=excluded.relevance_score, scraped_content=excluded.scraped_content,
                cve_ids=excluded.cve_ids, content_type=excluded.content_type",
            params![
                e.id, e.title, e.description, e.severity.as_deref().unwrap_or("unknown"),
                e.published.to_rfc3339(), source_str(e.source), e.url, e.llm_summary,
                e.ascii_diagram, e.relevance_score, e.scraped_content,
                serde_json::to_string(&e.cve_ids)?, e.content_type,
            ],
        )?;
        Ok(())
    }

    pub fn delete_entry(&self, id: &str) -> anyhow::Result<()> {
        self.conn.execute("DELETE FROM entries WHERE id=?1", params![id])?;
        Ok(())
    }

    pub fn clear_llm(&self, id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE entries SET llm_summary=NULL, ascii_diagram=NULL, relevance_score=NULL, cve_ids='[]' WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }
}

fn source_str(s: FeedSource) -> &'static str {
    match s {
        FeedSource::Nvd => "nvd", FeedSource::Cisa => "cisa", FeedSource::GitHub => "github",
        FeedSource::Microsoft => "microsoft", FeedSource::Cert => "cert",
        FeedSource::Research => "research", FeedSource::Community => "community",
        FeedSource::Exploit => "exploit", FeedSource::News => "news",
    }
}

fn parse_source(s: &str) -> FeedSource {
    match s {
        "nvd" => FeedSource::Nvd, "cisa" => FeedSource::Cisa, "github" => FeedSource::GitHub,
        "microsoft" => FeedSource::Microsoft, "cert" => FeedSource::Cert,
        "research" => FeedSource::Research, "community" => FeedSource::Community,
        "exploit" => FeedSource::Exploit, _ => FeedSource::News,
    }
}
