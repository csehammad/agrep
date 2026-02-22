use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Domain {
    Auto,
    Code,
    Legal,
    Docs,
    Logs,
}

impl Domain {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "code" => Some(Self::Code),
            "legal" => Some(Self::Legal),
            "docs" => Some(Self::Docs),
            "logs" => Some(Self::Logs),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Code => "code",
            Self::Legal => "legal",
            Self::Docs => "docs",
            Self::Logs => "logs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Jsonl,
    Table,
}

impl OutputFormat {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "table" => Some(Self::Table),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Config {
    command: String,
    query: String,
    path: PathBuf,
    domain: Domain,
    mode: String,
    format: OutputFormat,
    max_results: usize,
    context_lines: usize,
    show_plan: bool,
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
}

#[derive(Debug)]
struct QueryPlan {
    intent: String,
    terms: Vec<String>,
    expanded_terms: Vec<String>,
    path_boosts: Vec<String>,
    excludes: Vec<String>,
}

#[derive(Debug, Clone)]
struct MatchRecord {
    id: String,
    source_type: String,
    path: String,
    anchor: String,
    line_text: String,
    score: f64,
    score_breakdown: BTreeMap<String, f64>,
    confidence: f64,
    parse_error: bool,
    generated: bool,
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            print_usage();
            std::process::exit(2);
        }
    };

    if cfg.command != "query" {
        eprintln!("Unsupported command: {}", cfg.command);
        print_usage();
        std::process::exit(2);
    }
    let _mode = cfg.mode.as_str();

    let plan = build_query_plan(&cfg.query, cfg.domain);
    if cfg.show_plan {
        print_plan_json(&plan);
    }

    let files = collect_files(
        &cfg.path,
        &cfg.include_patterns,
        &cfg.exclude_patterns,
    );

    let mut results = Vec::new();
    for file in files {
        let guessed_domain = detect_domain(&file);
        if cfg.domain != Domain::Auto && guessed_domain != cfg.domain {
            continue;
        }
        scan_file(&file, guessed_domain, &plan, cfg.context_lines, &mut results);
    }

    results.sort_by(compare_match_records);
    if results.len() > cfg.max_results {
        results.truncate(cfg.max_results);
    }

    match cfg.format {
        OutputFormat::Jsonl => {
            for record in &results {
                print_match_json(record);
            }
        }
        OutputFormat::Table => print_table(&results),
    }
}

fn parse_args() -> Result<Config, String> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err("Missing required arguments".to_string());
    }

    let command = args.remove(1);
    let query = args.remove(1);

    let mut path = PathBuf::from(".");
    let mut domain = Domain::Auto;
    let mut mode = "hybrid".to_string();
    let mut format = OutputFormat::Jsonl;
    let mut max_results = 50;
    let mut context_lines = 0usize;
    let mut show_plan = false;
    let mut include_patterns = Vec::new();
    let mut exclude_patterns = vec!["/.git/".to_string(), "/target/".to_string()];

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                let v = args.get(i).ok_or("--path requires value")?;
                path = PathBuf::from(v);
            }
            "--domain" => {
                i += 1;
                let v = args.get(i).ok_or("--domain requires value")?;
                domain = Domain::parse(v)
                    .ok_or_else(|| format!("Invalid domain: {}", v))?;
            }
            "--mode" => {
                i += 1;
                let v = args.get(i).ok_or("--mode requires value")?;
                mode = v.clone();
            }
            "--format" => {
                i += 1;
                let v = args.get(i).ok_or("--format requires value")?;
                format = OutputFormat::parse(v)
                    .ok_or_else(|| format!("Invalid format: {}", v))?;
            }
            "--max-results" => {
                i += 1;
                let v = args.get(i).ok_or("--max-results requires value")?;
                max_results = v
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --max-results: {}", v))?;
            }
            "--context-lines" => {
                i += 1;
                let v = args.get(i).ok_or("--context-lines requires value")?;
                context_lines = v
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid --context-lines: {}", v))?;
            }
            "--include" => {
                i += 1;
                let v = args.get(i).ok_or("--include requires value")?;
                include_patterns.push(v.clone());
            }
            "--exclude" => {
                i += 1;
                let v = args.get(i).ok_or("--exclude requires value")?;
                exclude_patterns.push(v.clone());
            }
            "--show-plan" => {
                show_plan = true;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
        i += 1;
    }

    Ok(Config {
        command,
        query,
        path,
        domain,
        mode,
        format,
        max_results,
        context_lines,
        show_plan,
        include_patterns,
        exclude_patterns,
    })
}

fn build_query_plan(query: &str, domain: Domain) -> QueryPlan {
    let lower = query.to_lowercase();
    let terms: Vec<String> = lower
        .split_whitespace()
        .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut expanded = BTreeSet::new();
    for term in &terms {
        expanded.insert(term.clone());
    }

    if lower.contains("auth") || lower.contains("authentication") || lower.contains("authorization") {
        for t in [
            "auth",
            "authenticate",
            "authorization",
            "authorize",
            "guard",
            "middleware",
            "policy",
            "rbac",
            "acl",
            "jwt",
            "session",
            "permission",
        ] {
            expanded.insert(t.to_string());
        }
    }

    if matches!(domain, Domain::Legal | Domain::Auto) {
        if lower.contains("termination") {
            for t in ["termination", "terminate", "for convenience", "material breach", "notice"] {
                expanded.insert(t.to_string());
            }
        }
    }

    let mut path_boosts = vec![];
    match domain {
        Domain::Code | Domain::Auto => {
            path_boosts.extend([
                "auth", "security", "middleware", "guard", "policy", "api", "routes",
            ]
            .iter()
            .map(|s| s.to_string()));
        }
        Domain::Legal => {
            path_boosts.extend(["contracts", "legal", "msa", "dpa"].iter().map(|s| s.to_string()));
        }
        Domain::Docs => {
            path_boosts.extend(["docs", "handbook", "guide"].iter().map(|s| s.to_string()));
        }
        Domain::Logs => {
            path_boosts.extend(["logs", "events", "audit"].iter().map(|s| s.to_string()));
        }
    }

    QueryPlan {
        intent: infer_intent(&lower),
        terms,
        expanded_terms: expanded.into_iter().collect(),
        path_boosts,
        excludes: vec![".git".to_string(), "target".to_string()],
    }
}

fn infer_intent(lower: &str) -> String {
    if lower.contains("where") {
        "locate".to_string()
    } else if lower.contains("impact") {
        "impact-analysis".to_string()
    } else if lower.contains("policy") || lower.contains("compliance") {
        "policy-check".to_string()
    } else {
        "search".to_string()
    }
}

fn collect_files(root: &Path, include_patterns: &[String], exclude_patterns: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        let path_str = root.to_string_lossy();
        if !exclude_patterns.iter().any(|pat| path_str.contains(pat))
            && (include_patterns.is_empty() || include_patterns.iter().any(|pat| path_str.contains(pat)))
            && !looks_binary(root)
        {
            out.push(root.to_path_buf());
        }
        return out;
    }
    visit_dir(root, include_patterns, exclude_patterns, &mut out);
    out
}

fn visit_dir(path: &Path, include_patterns: &[String], exclude_patterns: &[String], out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let p = entry.path();
        let path_str = p.to_string_lossy();

        if exclude_patterns.iter().any(|pat| path_str.contains(pat)) {
            continue;
        }

        if p.is_dir() {
            visit_dir(&p, include_patterns, exclude_patterns, out);
            continue;
        }

        if !include_patterns.is_empty() && !include_patterns.iter().any(|pat| path_str.contains(pat)) {
            continue;
        }

        if looks_binary(&p) {
            continue;
        }

        out.push(p);
    }
}

fn looks_binary(path: &Path) -> bool {
    let mut f = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return true,
    };
    let mut buf = [0u8; 1024];
    let n = match std::io::Read::read(&mut f, &mut buf) {
        Ok(n) => n,
        Err(_) => return true,
    };
    buf[..n].contains(&0u8)
}

fn detect_domain(path: &Path) -> Domain {
    let p = path.to_string_lossy().to_lowercase();
    // Path hints take precedence so legal markdown/text files are classified correctly.
    if p.contains("contract")
        || p.contains("legal")
        || p.contains("agreement")
        || p.contains("msa")
        || p.contains("dpa")
        || p.contains("terms")
    {
        return Domain::Legal;
    }
    if p.contains("logs") || p.ends_with(".log") {
        return Domain::Logs;
    }
    if p.contains("docs") || p.contains("handbook") || p.contains("guide") {
        return Domain::Docs;
    }

    let ext = path.extension().and_then(OsStr::to_str).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "rs" | "go" | "py" | "js" | "ts" | "tsx" | "jsx" | "java" | "kt" | "c" | "h" | "cpp" | "cs" => Domain::Code,
        "md" | "txt" | "rst" => Domain::Docs,
        "log" => Domain::Logs,
        "pdf" | "docx" => Domain::Legal,
        _ => Domain::Code,
    }
}

fn scan_file(path: &Path, domain: Domain, plan: &QueryPlan, context_lines: usize, out: &mut Vec<MatchRecord>) {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let lower_lines: Vec<String> = lines.iter().map(|l| l.to_lowercase()).collect();
    for (idx, lower_line) in lower_lines.iter().enumerate() {
        let mut matched_terms = 0usize;
        for term in &plan.expanded_terms {
            if lower_line.contains(term) {
                matched_terms += 1;
            }
        }
        if matched_terms == 0 {
            continue;
        }

        let mut score_breakdown = BTreeMap::new();
        let term_score = (matched_terms as f64 / plan.expanded_terms.len().max(1) as f64).min(1.0);
        score_breakdown.insert("term".to_string(), term_score * 0.5);

        let path_s = path.to_string_lossy().to_lowercase();
        let mut path_score: f64 = 0.0;
        for boost in &plan.path_boosts {
            if path_s.contains(boost) {
                path_score += 0.05;
            }
        }
        path_score = path_score.min(0.25);
        score_breakdown.insert("path".to_string(), path_score);

        let domain_score = domain_alignment_score(domain, path);
        score_breakdown.insert("domain".to_string(), domain_score);

        let intent_score = if plan.intent == "locate" { 0.1 } else { 0.05 };
        score_breakdown.insert("intent".to_string(), intent_score);

        let score: f64 = score_breakdown.values().sum();

        let rendered_line = if context_lines == 0 {
            lines[idx].clone()
        } else {
            render_context(&lines, idx, context_lines)
        };

        let anchor = format!("line-{}", idx + 1);
        let id = stable_id(&path.to_string_lossy(), &anchor, &rendered_line, &plan.intent);

        out.push(MatchRecord {
            id,
            source_type: domain.as_str().to_string(),
            path: path.to_string_lossy().to_string(),
            anchor,
            line_text: rendered_line,
            score,
            score_breakdown,
            confidence: (0.5 + score).min(0.99),
            parse_error: false,
            generated: path.to_string_lossy().contains("generated"),
        });
    }
}

fn domain_alignment_score(domain: Domain, path: &Path) -> f64 {
    let p = path.to_string_lossy().to_lowercase();
    match domain {
        Domain::Code => {
            if p.contains("src") || p.contains("app") { 0.2 } else { 0.1 }
        }
        Domain::Legal => {
            if p.contains("contract") || p.contains("legal") { 0.2 } else { 0.1 }
        }
        Domain::Docs => {
            if p.contains("docs") { 0.2 } else { 0.1 }
        }
        Domain::Logs => {
            if p.contains("log") { 0.2 } else { 0.1 }
        }
        Domain::Auto => 0.1,
    }
}

fn render_context(lines: &[String], idx: usize, ctx: usize) -> String {
    let start = idx.saturating_sub(ctx);
    let end = (idx + ctx + 1).min(lines.len());
    let mut parts = Vec::new();
    for (i, line) in lines[start..end].iter().enumerate() {
        let absolute = start + i + 1;
        parts.push(format!("{}:{}", absolute, line));
    }
    parts.join("\\n")
}

fn stable_id(path: &str, anchor: &str, snippet: &str, intent: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    anchor.hash(&mut h);
    snippet.hash(&mut h);
    intent.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn compare_match_records(a: &MatchRecord, b: &MatchRecord) -> Ordering {
    b.score
        .partial_cmp(&a.score)
        .unwrap_or(Ordering::Equal)
        .then_with(|| a.path.cmp(&b.path))
        .then_with(|| a.anchor.cmp(&b.anchor))
}

fn print_plan_json(plan: &QueryPlan) {
    println!(
        "{{\"type\":\"nl_plan\",\"intent\":\"{}\",\"terms\":{},\"expanded_terms\":{},\"path_boosts\":{},\"excludes\":{}}}",
        escape_json(&plan.intent),
        json_array(&plan.terms),
        json_array(&plan.expanded_terms),
        json_array(&plan.path_boosts),
        json_array(&plan.excludes),
    );
}

fn print_match_json(record: &MatchRecord) {
    let mut breakdown_parts = Vec::new();
    for (k, v) in &record.score_breakdown {
        breakdown_parts.push(format!("\"{}\":{:.4}", escape_json(k), v));
    }
    println!(
        "{{\"id\":\"{}\",\"source_type\":\"{}\",\"path\":\"{}\",\"anchor\":\"{}\",\"snippet\":\"{}\",\"score\":{:.4},\"score_breakdown\":{{{}}},\"signals\":{{\"confidence\":{:.4},\"parse_error\":{},\"generated\":{}}}}}",
        escape_json(&record.id),
        escape_json(&record.source_type),
        escape_json(&record.path),
        escape_json(&record.anchor),
        escape_json(&record.line_text),
        record.score,
        breakdown_parts.join(","),
        record.confidence,
        record.parse_error,
        record.generated
    );
}

fn json_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json(item));
        out.push('"');
    }
    out.push(']');
    out
}

fn print_table(records: &[MatchRecord]) {
    println!("SCORE  DOMAIN  PATH:ANCHOR  SNIPPET");
    for r in records {
        let snippet = if r.line_text.len() > 90 {
            format!("{}...", &r.line_text[..90])
        } else {
            r.line_text.clone()
        };
        println!(
            "{:.3}  {:<6}  {}:{}  {}",
            r.score, r.source_type, r.path, r.anchor, snippet
        );
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn print_usage() {
    eprintln!(
        "Usage:\n  agrep query \"<query>\" [--path <dir>] [--domain auto|code|legal|docs|logs] [--mode text|hybrid] [--format jsonl|table] [--max-results <n>] [--context-lines <n>] [--include <pattern>] [--exclude <pattern>] [--show-plan]"
    );
}
