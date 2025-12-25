//! Taint Analysis module for security vulnerability detection.
//!
//! This module provides taint tracking capabilities to detect injection
//! vulnerabilities, data leaks, and missing sanitization in code.
//!
//! # Features
//! - Taint source identification (user input, file reads, network data)
//! - Taint sink detection (SQL queries, command execution, HTML output)
//! - Taint propagation through data flow
//! - Sanitizer recognition
//! - Vulnerability detection (SQL injection, XSS, command injection, path traversal)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Confidence level for taint analysis results
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence - may be false positive
    Low,
    /// Medium confidence
    Medium,
    /// High confidence - likely real vulnerability
    High,
}

/// Severity of a detected vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational finding
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity - immediate action required
    Critical,
}

/// Types of taint sources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// HTTP request parameters, form data, URL params
    UserInput {
        /// Specific input type (query, body, header, cookie)
        input_type: String,
    },
    /// File content read
    FileRead,
    /// Database query results
    DatabaseQuery,
    /// Environment variables
    Environment,
    /// Network socket data
    Network,
    /// Command line arguments
    CommandArgs,
    /// Deserialized data
    Deserialization,
    /// User-defined custom source
    Custom { name: String },
}

impl SourceKind {
    /// Get display name for this source kind
    pub fn display_name(&self) -> String {
        match self {
            SourceKind::UserInput { input_type } => format!("User Input ({})", input_type),
            SourceKind::FileRead => "File Read".to_string(),
            SourceKind::DatabaseQuery => "Database Query".to_string(),
            SourceKind::Environment => "Environment Variable".to_string(),
            SourceKind::Network => "Network Data".to_string(),
            SourceKind::CommandArgs => "Command Args".to_string(),
            SourceKind::Deserialization => "Deserialized Data".to_string(),
            SourceKind::Custom { name } => format!("Custom ({})", name),
        }
    }
}

/// Types of taint sinks (dangerous operations)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    /// SQL query execution - potential SQL injection
    SqlQuery,
    /// Shell command execution - potential command injection
    CommandExec,
    /// HTML/template output - potential XSS
    HtmlOutput,
    /// File system operations - potential path traversal
    FileWrite,
    /// File path operations - potential path traversal
    FilePath,
    /// Code evaluation (eval, exec) - potential code injection
    Eval,
    /// Object deserialization - potential object injection
    Deserialization,
    /// LDAP query - potential LDAP injection
    LdapQuery,
    /// XML parsing - potential XXE
    XmlParse,
    /// Regular expression - potential ReDoS
    Regex,
    /// Logging - potential log injection
    Logging,
    /// Redirect URL - potential open redirect
    Redirect,
    /// User-defined custom sink
    Custom { name: String },
}

impl SinkKind {
    /// Get the vulnerability type associated with this sink
    pub fn vulnerability_type(&self) -> VulnerabilityKind {
        match self {
            SinkKind::SqlQuery => VulnerabilityKind::SqlInjection,
            SinkKind::CommandExec => VulnerabilityKind::CommandInjection,
            SinkKind::HtmlOutput => VulnerabilityKind::Xss,
            SinkKind::FileWrite | SinkKind::FilePath => VulnerabilityKind::PathTraversal,
            SinkKind::Eval => VulnerabilityKind::CodeInjection,
            SinkKind::Deserialization => VulnerabilityKind::InsecureDeserialization,
            SinkKind::LdapQuery => VulnerabilityKind::LdapInjection,
            SinkKind::XmlParse => VulnerabilityKind::XxeInjection,
            SinkKind::Regex => VulnerabilityKind::ReDoS,
            SinkKind::Logging => VulnerabilityKind::LogInjection,
            SinkKind::Redirect => VulnerabilityKind::OpenRedirect,
            SinkKind::Custom { name } => VulnerabilityKind::Custom { name: name.clone() },
        }
    }

    /// Get display name for this sink kind
    pub fn display_name(&self) -> String {
        match self {
            SinkKind::SqlQuery => "SQL Query".to_string(),
            SinkKind::CommandExec => "Command Execution".to_string(),
            SinkKind::HtmlOutput => "HTML Output".to_string(),
            SinkKind::FileWrite => "File Write".to_string(),
            SinkKind::FilePath => "File Path".to_string(),
            SinkKind::Eval => "Code Eval".to_string(),
            SinkKind::Deserialization => "Deserialization".to_string(),
            SinkKind::LdapQuery => "LDAP Query".to_string(),
            SinkKind::XmlParse => "XML Parse".to_string(),
            SinkKind::Regex => "Regex".to_string(),
            SinkKind::Logging => "Logging".to_string(),
            SinkKind::Redirect => "Redirect".to_string(),
            SinkKind::Custom { name } => format!("Custom ({})", name),
        }
    }
}

/// Types of vulnerabilities detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityKind {
    /// SQL Injection (CWE-89)
    SqlInjection,
    /// Cross-Site Scripting (CWE-79)
    Xss,
    /// Command Injection (CWE-78)
    CommandInjection,
    /// Path Traversal (CWE-22)
    PathTraversal,
    /// Code Injection (CWE-94)
    CodeInjection,
    /// Insecure Deserialization (CWE-502)
    InsecureDeserialization,
    /// LDAP Injection (CWE-90)
    LdapInjection,
    /// XML External Entity (CWE-611)
    XxeInjection,
    /// Regular Expression DoS (CWE-1333)
    ReDoS,
    /// Log Injection (CWE-117)
    LogInjection,
    /// Open Redirect (CWE-601)
    OpenRedirect,
    /// Custom vulnerability type
    Custom { name: String },
}

impl VulnerabilityKind {
    /// Get CWE ID for this vulnerability
    pub fn cwe_id(&self) -> Option<&'static str> {
        match self {
            VulnerabilityKind::SqlInjection => Some("CWE-89"),
            VulnerabilityKind::Xss => Some("CWE-79"),
            VulnerabilityKind::CommandInjection => Some("CWE-78"),
            VulnerabilityKind::PathTraversal => Some("CWE-22"),
            VulnerabilityKind::CodeInjection => Some("CWE-94"),
            VulnerabilityKind::InsecureDeserialization => Some("CWE-502"),
            VulnerabilityKind::LdapInjection => Some("CWE-90"),
            VulnerabilityKind::XxeInjection => Some("CWE-611"),
            VulnerabilityKind::ReDoS => Some("CWE-1333"),
            VulnerabilityKind::LogInjection => Some("CWE-117"),
            VulnerabilityKind::OpenRedirect => Some("CWE-601"),
            VulnerabilityKind::Custom { .. } => None,
        }
    }

    /// Get OWASP Top 10 category if applicable
    pub fn owasp_category(&self) -> Option<&'static str> {
        match self {
            VulnerabilityKind::SqlInjection
            | VulnerabilityKind::CommandInjection
            | VulnerabilityKind::LdapInjection
            | VulnerabilityKind::XxeInjection => Some("A03:2021 - Injection"),
            VulnerabilityKind::Xss => Some("A03:2021 - Injection"),
            VulnerabilityKind::PathTraversal => Some("A01:2021 - Broken Access Control"),
            VulnerabilityKind::InsecureDeserialization => {
                Some("A08:2021 - Software and Data Integrity Failures")
            }
            VulnerabilityKind::OpenRedirect => Some("A01:2021 - Broken Access Control"),
            _ => None,
        }
    }

    /// Get default severity for this vulnerability type
    pub fn default_severity(&self) -> Severity {
        match self {
            VulnerabilityKind::SqlInjection => Severity::Critical,
            VulnerabilityKind::CommandInjection => Severity::Critical,
            VulnerabilityKind::CodeInjection => Severity::Critical,
            VulnerabilityKind::InsecureDeserialization => Severity::High,
            VulnerabilityKind::PathTraversal => Severity::High,
            VulnerabilityKind::Xss => Severity::High,
            VulnerabilityKind::XxeInjection => Severity::High,
            VulnerabilityKind::LdapInjection => Severity::High,
            VulnerabilityKind::OpenRedirect => Severity::Medium,
            VulnerabilityKind::LogInjection => Severity::Medium,
            VulnerabilityKind::ReDoS => Severity::Medium,
            VulnerabilityKind::Custom { .. } => Severity::Medium,
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &str {
        match self {
            VulnerabilityKind::SqlInjection => "SQL Injection",
            VulnerabilityKind::Xss => "Cross-Site Scripting (XSS)",
            VulnerabilityKind::CommandInjection => "Command Injection",
            VulnerabilityKind::PathTraversal => "Path Traversal",
            VulnerabilityKind::CodeInjection => "Code Injection",
            VulnerabilityKind::InsecureDeserialization => "Insecure Deserialization",
            VulnerabilityKind::LdapInjection => "LDAP Injection",
            VulnerabilityKind::XxeInjection => "XXE Injection",
            VulnerabilityKind::ReDoS => "Regular Expression DoS",
            VulnerabilityKind::LogInjection => "Log Injection",
            VulnerabilityKind::OpenRedirect => "Open Redirect",
            VulnerabilityKind::Custom { name } => name,
        }
    }
}

/// A taint label attached to data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Kind of source that introduced this taint
    pub source_kind: SourceKind,
    /// Location where taint was introduced
    pub origin_file: String,
    pub origin_line: usize,
    /// Variable that was tainted
    pub variable: String,
    /// Confidence level
    pub confidence: Confidence,
}

/// A taint source location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Unique identifier
    pub id: String,
    /// Kind of source
    pub kind: SourceKind,
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Variable name that receives tainted data
    pub variable: String,
    /// Code snippet
    pub code: String,
    /// Confidence
    pub confidence: Confidence,
}

/// A taint sink location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Unique identifier
    pub id: String,
    /// Kind of sink
    pub kind: SinkKind,
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Function/method being called
    pub function: String,
    /// Code snippet
    pub code: String,
    /// Which argument position is dangerous (0-indexed)
    pub dangerous_arg: usize,
}

/// A step in the taint propagation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Code snippet
    pub code: String,
    /// Variable carrying taint at this step
    pub variable: String,
    /// Type of operation
    pub operation: TaintOperation,
}

/// Types of operations in taint propagation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintOperation {
    /// Source introduces taint
    Source,
    /// Assignment propagates taint
    Assignment,
    /// Function call (may propagate or sanitize)
    FunctionCall { function: String },
    /// String concatenation
    Concatenation,
    /// Array/object access
    PropertyAccess,
    /// Return from function
    Return,
    /// Sink receives taint
    Sink,
}

/// A sanitizer that removes taint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sanitizer {
    /// Sanitizer identifier
    pub id: String,
    /// Function name
    pub function: String,
    /// What kind of taint it sanitizes for
    pub sanitizes_for: Vec<SinkKind>,
    /// File path where used
    pub file_path: String,
    /// Line number
    pub line: usize,
}

/// A complete taint flow from source to sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Unique identifier
    pub id: String,
    /// The taint source
    pub source: TaintSource,
    /// The taint sink
    pub sink: TaintSink,
    /// Path from source to sink
    pub path: Vec<TaintStep>,
    /// Sanitizers encountered (if any)
    pub sanitizers: Vec<Sanitizer>,
    /// Detected vulnerability (if unsanitized)
    pub vulnerability: Option<VulnerabilityKind>,
    /// Severity if vulnerable
    pub severity: Option<Severity>,
    /// Confidence level
    pub confidence: Confidence,
    /// Is the flow properly sanitized?
    pub is_sanitized: bool,
}

impl TaintFlow {
    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        if let Some(ref vuln) = self.vulnerability {
            let severity_icon = match self.severity.unwrap_or(Severity::Medium) {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };

            md.push_str(&format!(
                "## {} {} ({})\n\n",
                severity_icon,
                vuln.display_name(),
                vuln.cwe_id().unwrap_or("N/A")
            ));

            if let Some(owasp) = vuln.owasp_category() {
                md.push_str(&format!("**OWASP**: {}\n\n", owasp));
            }
        } else if self.is_sanitized {
            md.push_str("## ✅ Sanitized Flow\n\n");
        }

        // Source
        md.push_str("### Source\n\n");
        md.push_str(&format!(
            "- **Type**: {}\n",
            self.source.kind.display_name()
        ));
        md.push_str(&format!(
            "- **Location**: `{}:{}`\n",
            self.source.file_path, self.source.line
        ));
        md.push_str(&format!("- **Variable**: `{}`\n", self.source.variable));
        md.push_str(&format!("- **Code**: `{}`\n\n", self.source.code));

        // Path
        if !self.path.is_empty() {
            md.push_str("### Data Flow Path\n\n");
            for (i, step) in self.path.iter().enumerate() {
                md.push_str(&format!(
                    "{}. **{}:{}** - `{}` ({:?})\n",
                    i + 1,
                    step.file_path,
                    step.line,
                    step.code,
                    step.operation
                ));
            }
            md.push('\n');
        }

        // Sanitizers
        if !self.sanitizers.is_empty() {
            md.push_str("### Sanitizers Applied\n\n");
            for san in &self.sanitizers {
                md.push_str(&format!(
                    "- `{}` at `{}:{}`\n",
                    san.function, san.file_path, san.line
                ));
            }
            md.push('\n');
        }

        // Sink
        md.push_str("### Sink\n\n");
        md.push_str(&format!("- **Type**: {}\n", self.sink.kind.display_name()));
        md.push_str(&format!(
            "- **Location**: `{}:{}`\n",
            self.sink.file_path, self.sink.line
        ));
        md.push_str(&format!("- **Function**: `{}`\n", self.sink.function));
        md.push_str(&format!("- **Code**: `{}`\n\n", self.sink.code));

        md
    }
}

/// Taint analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    /// File or repository analyzed
    pub target: String,
    /// All identified sources
    pub sources: Vec<TaintSource>,
    /// All identified sinks
    pub sinks: Vec<TaintSink>,
    /// All taint flows found
    pub flows: Vec<TaintFlow>,
    /// Vulnerabilities found (unsanitized flows)
    pub vulnerabilities: Vec<TaintFlow>,
    /// Statistics
    pub stats: TaintStats,
}

/// Statistics from taint analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintStats {
    pub files_analyzed: usize,
    pub functions_analyzed: usize,
    pub sources_found: usize,
    pub sinks_found: usize,
    pub flows_found: usize,
    pub vulnerabilities_found: usize,
    pub sanitized_flows: usize,
    pub analysis_time_ms: u64,
}

impl TaintAnalysisResult {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            sources: Vec::new(),
            sinks: Vec::new(),
            flows: Vec::new(),
            vulnerabilities: Vec::new(),
            stats: TaintStats::default(),
        }
    }

    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Taint Analysis: {}\n\n", self.target));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **Files Analyzed**: {}\n",
            self.stats.files_analyzed
        ));
        md.push_str(&format!(
            "- **Sources Found**: {}\n",
            self.stats.sources_found
        ));
        md.push_str(&format!("- **Sinks Found**: {}\n", self.stats.sinks_found));
        md.push_str(&format!("- **Taint Flows**: {}\n", self.stats.flows_found));
        md.push_str(&format!(
            "- **Vulnerabilities**: {}\n",
            self.stats.vulnerabilities_found
        ));
        md.push_str(&format!(
            "- **Sanitized Flows**: {}\n\n",
            self.stats.sanitized_flows
        ));

        // Vulnerabilities
        if !self.vulnerabilities.is_empty() {
            md.push_str("## Vulnerabilities Found\n\n");

            // Group by severity
            let mut by_severity: HashMap<Severity, Vec<&TaintFlow>> = HashMap::new();
            for flow in &self.vulnerabilities {
                let sev = flow.severity.unwrap_or(Severity::Medium);
                by_severity.entry(sev).or_default().push(flow);
            }

            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ] {
                if let Some(flows) = by_severity.get(&severity) {
                    for flow in flows {
                        md.push_str(&flow.to_markdown());
                        md.push_str("---\n\n");
                    }
                }
            }
        } else {
            md.push_str("## No Vulnerabilities Found\n\n");
            md.push_str("All taint flows are properly sanitized.\n\n");
        }

        // Sources summary
        if !self.sources.is_empty() {
            md.push_str("## Taint Sources\n\n");
            md.push_str("| Location | Type | Variable |\n");
            md.push_str("|----------|------|----------|\n");
            for source in &self.sources {
                md.push_str(&format!(
                    "| `{}:{}` | {} | `{}` |\n",
                    source.file_path,
                    source.line,
                    source.kind.display_name(),
                    source.variable
                ));
            }
            md.push('\n');
        }

        // Sinks summary
        if !self.sinks.is_empty() {
            md.push_str("## Taint Sinks\n\n");
            md.push_str("| Location | Type | Function |\n");
            md.push_str("|----------|------|----------|\n");
            for sink in &self.sinks {
                md.push_str(&format!(
                    "| `{}:{}` | {} | `{}` |\n",
                    sink.file_path,
                    sink.line,
                    sink.kind.display_name(),
                    sink.function
                ));
            }
        }

        md
    }
}

/// Pattern for identifying taint sources
#[derive(Debug, Clone)]
pub struct SourcePattern {
    /// Pattern name
    pub name: String,
    /// Source kind this pattern detects
    pub kind: SourceKind,
    /// Languages this pattern applies to
    pub languages: Vec<String>,
    /// Function/method patterns (regex-like)
    pub function_patterns: Vec<String>,
    /// Object property patterns
    pub property_patterns: Vec<String>,
    /// Confidence level for matches
    pub confidence: Confidence,
}

/// Pattern for identifying taint sinks
#[derive(Debug, Clone)]
pub struct SinkPattern {
    /// Pattern name
    pub name: String,
    /// Sink kind
    pub kind: SinkKind,
    /// Languages this pattern applies to
    pub languages: Vec<String>,
    /// Function/method patterns
    pub function_patterns: Vec<String>,
    /// Which argument is dangerous (0-indexed)
    pub dangerous_arg: usize,
}

/// Pattern for identifying sanitizers
#[derive(Debug, Clone)]
pub struct SanitizerPattern {
    /// Pattern name
    pub name: String,
    /// Function patterns
    pub function_patterns: Vec<String>,
    /// What sinks this sanitizes for
    pub sanitizes_for: Vec<SinkKind>,
    /// Languages
    pub languages: Vec<String>,
}

/// Main taint analyzer
pub struct TaintAnalyzer {
    /// Source patterns
    source_patterns: Vec<SourcePattern>,
    /// Sink patterns
    sink_patterns: Vec<SinkPattern>,
    /// Sanitizer patterns
    sanitizer_patterns: Vec<SanitizerPattern>,
    /// Language being analyzed
    language: String,
}

impl TaintAnalyzer {
    /// Create a new taint analyzer with default patterns
    pub fn new(language: &str) -> Self {
        let mut analyzer = Self {
            source_patterns: Vec::new(),
            sink_patterns: Vec::new(),
            sanitizer_patterns: Vec::new(),
            language: language.to_string(),
        };

        analyzer.load_default_patterns();
        analyzer
    }

    /// Load default security patterns for common frameworks
    fn load_default_patterns(&mut self) {
        self.load_source_patterns();
        self.load_sink_patterns();
        self.load_sanitizer_patterns();
    }

    fn load_source_patterns(&mut self) {
        // Python Flask/Django sources
        self.source_patterns.push(SourcePattern {
            name: "flask_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "request.args".to_string(),
                "request.form".to_string(),
                "request.data".to_string(),
                "request.json".to_string(),
                "request.values".to_string(),
                "request.cookies".to_string(),
                "request.headers".to_string(),
                "request.files".to_string(),
            ],
            confidence: Confidence::High,
        });

        self.source_patterns.push(SourcePattern {
            name: "django_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "request.GET".to_string(),
                "request.POST".to_string(),
                "request.COOKIES".to_string(),
                "request.META".to_string(),
                "request.body".to_string(),
            ],
            confidence: Confidence::High,
        });

        // JavaScript/TypeScript Express sources
        self.source_patterns.push(SourcePattern {
            name: "express_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "req.query".to_string(),
                "req.body".to_string(),
                "req.params".to_string(),
                "req.cookies".to_string(),
                "req.headers".to_string(),
            ],
            confidence: Confidence::High,
        });

        // Rust web framework sources
        self.source_patterns.push(SourcePattern {
            name: "actix_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["rust".to_string()],
            function_patterns: vec![
                "web::Query".to_string(),
                "web::Form".to_string(),
                "web::Json".to_string(),
                "web::Path".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        });

        // Go http sources
        self.source_patterns.push(SourcePattern {
            name: "go_http_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["go".to_string()],
            function_patterns: vec![
                "r.URL.Query".to_string(),
                "r.FormValue".to_string(),
                "r.PostFormValue".to_string(),
                "r.Header.Get".to_string(),
            ],
            property_patterns: vec!["r.Body".to_string()],
            confidence: Confidence::High,
        });

        // File read sources
        self.source_patterns.push(SourcePattern {
            name: "file_read".to_string(),
            kind: SourceKind::FileRead,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "open(".to_string(),
                "read(".to_string(),
                "readFile".to_string(),
                "read_to_string".to_string(),
                "fs.readFile".to_string(),
                "ioutil.ReadFile".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        });

        // Environment variable sources
        self.source_patterns.push(SourcePattern {
            name: "env_var".to_string(),
            kind: SourceKind::Environment,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "os.environ".to_string(),
                "os.getenv".to_string(),
                "process.env".to_string(),
                "std::env::var".to_string(),
                "env::var".to_string(),
                "os.Getenv".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        });

        // PHP superglobals - user input
        self.source_patterns.push(SourcePattern {
            name: "php_superglobals".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["php".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "$_GET".to_string(),
                "$_POST".to_string(),
                "$_REQUEST".to_string(),
                "$_COOKIE".to_string(),
                "$_SERVER".to_string(),
                "$_FILES".to_string(),
            ],
            confidence: Confidence::High,
        });

        // PHP file sources
        self.source_patterns.push(SourcePattern {
            name: "php_file_read".to_string(),
            kind: SourceKind::FileRead,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "file_get_contents(".to_string(),
                "fread(".to_string(),
                "fgets(".to_string(),
                "file(".to_string(),
                "readfile(".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        });

        // Java Servlet API sources
        self.source_patterns.push(SourcePattern {
            name: "java_servlet_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "getParameter(".to_string(),
                "getParameterValues(".to_string(),
                "getParameterMap(".to_string(),
                "getInputStream(".to_string(),
                "getReader(".to_string(),
                "getHeader(".to_string(),
                "getHeaders(".to_string(),
                "getCookies(".to_string(),
                "getQueryString(".to_string(),
                "getRequestURI(".to_string(),
                "getPathInfo(".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        });

        // Java Spring sources
        self.source_patterns.push(SourcePattern {
            name: "java_spring_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "@RequestParam".to_string(),
                "@PathVariable".to_string(),
                "@RequestBody".to_string(),
                "@RequestHeader".to_string(),
                "@CookieValue".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        });

        // C# ASP.NET sources
        self.source_patterns.push(SourcePattern {
            name: "csharp_aspnet_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["csharp".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "Request.QueryString".to_string(),
                "Request.Form".to_string(),
                "Request.Cookies".to_string(),
                "Request.Headers".to_string(),
                "Request.Body".to_string(),
                "Request.Path".to_string(),
                "Request.Query".to_string(),
            ],
            confidence: Confidence::High,
        });

        // C# ASP.NET Core sources
        self.source_patterns.push(SourcePattern {
            name: "csharp_aspnetcore_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "[FromQuery]".to_string(),
                "[FromBody]".to_string(),
                "[FromRoute]".to_string(),
                "[FromHeader]".to_string(),
                "[FromForm]".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        });

        // Ruby Rails sources
        self.source_patterns.push(SourcePattern {
            name: "ruby_rails_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["ruby".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "params[".to_string(),
                "request.params".to_string(),
                "request.query_parameters".to_string(),
                "request.body".to_string(),
                "cookies[".to_string(),
                "request.headers".to_string(),
            ],
            confidence: Confidence::High,
        });
    }

    fn load_sink_patterns(&mut self) {
        // SQL sinks
        self.sink_patterns.push(SinkPattern {
            name: "sql_execute".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "execute(".to_string(),
                "executemany(".to_string(),
                "raw(".to_string(),
                "query(".to_string(),
                "exec(".to_string(),
                "Query(".to_string(),
                "Exec(".to_string(),
                "sqlx::query".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Command execution sinks
        self.sink_patterns.push(SinkPattern {
            name: "command_exec".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "os.system".to_string(),
                "subprocess.call".to_string(),
                "subprocess.run".to_string(),
                "subprocess.Popen".to_string(),
                "exec(".to_string(),
                "spawn(".to_string(),
                "execSync".to_string(),
                "child_process".to_string(),
                "Command::new".to_string(),
                "std::process::Command".to_string(),
                "exec.Command".to_string(),
            ],
            dangerous_arg: 0,
        });

        // HTML output sinks (XSS)
        self.sink_patterns.push(SinkPattern {
            name: "html_output".to_string(),
            kind: SinkKind::HtmlOutput,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "innerHTML".to_string(),
                "outerHTML".to_string(),
                "document.write".to_string(),
                "render_template_string".to_string(),
                "dangerouslySetInnerHTML".to_string(),
                "res.send".to_string(),
                "res.write".to_string(),
            ],
            dangerous_arg: 0,
        });

        // File path sinks
        self.sink_patterns.push(SinkPattern {
            name: "file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "open(".to_string(),
                "readFile".to_string(),
                "writeFile".to_string(),
                "fs.open".to_string(),
                "File::open".to_string(),
                "std::fs::read".to_string(),
                "os.Open".to_string(),
                "ioutil.WriteFile".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Eval sinks
        self.sink_patterns.push(SinkPattern {
            name: "code_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "eval(".to_string(),
                "exec(".to_string(),
                "compile(".to_string(),
                "Function(".to_string(),
                "setTimeout(".to_string(),
                "setInterval(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Deserialization sinks
        self.sink_patterns.push(SinkPattern {
            name: "deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
            ],
            function_patterns: vec![
                "pickle.loads".to_string(),
                "yaml.load".to_string(),
                "yaml.unsafe_load".to_string(),
                "JSON.parse".to_string(),
                "deserialize".to_string(),
                "unmarshal".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Redirect sinks
        self.sink_patterns.push(SinkPattern {
            name: "redirect".to_string(),
            kind: SinkKind::Redirect,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "redirect(".to_string(),
                "location.href".to_string(),
                "location.replace".to_string(),
                "res.redirect".to_string(),
            ],
            dangerous_arg: 0,
        });

        // PHP SQL sinks
        self.sink_patterns.push(SinkPattern {
            name: "php_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "mysql_query(".to_string(),
                "mysqli_query(".to_string(),
                "mysqli_real_query(".to_string(),
                "pg_query(".to_string(),
                "pg_exec(".to_string(),
                "sqlite_query(".to_string(),
                "->query(".to_string(),
                "->exec(".to_string(),
                "->execute(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // PHP command injection sinks
        self.sink_patterns.push(SinkPattern {
            name: "php_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "exec(".to_string(),
                "shell_exec(".to_string(),
                "system(".to_string(),
                "passthru(".to_string(),
                "popen(".to_string(),
                "proc_open(".to_string(),
                "pcntl_exec(".to_string(),
                "`".to_string(), // backticks
            ],
            dangerous_arg: 0,
        });

        // PHP XSS sinks
        self.sink_patterns.push(SinkPattern {
            name: "php_xss".to_string(),
            kind: SinkKind::HtmlOutput,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "echo ".to_string(),
                "print ".to_string(),
                "printf(".to_string(),
                "print_r(".to_string(),
                "var_dump(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // PHP file path sinks
        self.sink_patterns.push(SinkPattern {
            name: "php_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "include(".to_string(),
                "include_once(".to_string(),
                "require(".to_string(),
                "require_once(".to_string(),
                "file_get_contents(".to_string(),
                "file_put_contents(".to_string(),
                "fopen(".to_string(),
                "readfile(".to_string(),
                "unlink(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // PHP eval sinks
        self.sink_patterns.push(SinkPattern {
            name: "php_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "eval(".to_string(),
                "assert(".to_string(),
                "preg_replace(".to_string(), // with /e modifier
                "create_function(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Java SQL sinks
        self.sink_patterns.push(SinkPattern {
            name: "java_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "executeQuery(".to_string(),
                "executeUpdate(".to_string(),
                "execute(".to_string(),
                "createStatement(".to_string(),
                "prepareStatement(".to_string(),
                "createNativeQuery(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Java command execution sinks
        self.sink_patterns.push(SinkPattern {
            name: "java_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "Runtime.getRuntime().exec(".to_string(),
                "ProcessBuilder(".to_string(),
                ".exec(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Java file path sinks
        self.sink_patterns.push(SinkPattern {
            name: "java_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "new File(".to_string(),
                "new FileInputStream(".to_string(),
                "new FileOutputStream(".to_string(),
                "Files.readAllBytes(".to_string(),
                "Files.write(".to_string(),
                "Paths.get(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Java deserialization sinks
        self.sink_patterns.push(SinkPattern {
            name: "java_deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "ObjectInputStream(".to_string(),
                "readObject(".to_string(),
                "readUnshared(".to_string(),
                "XMLDecoder(".to_string(),
                "XStream(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Java XXE sinks
        self.sink_patterns.push(SinkPattern {
            name: "java_xxe".to_string(),
            kind: SinkKind::XmlParse,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "DocumentBuilderFactory".to_string(),
                "SAXParserFactory".to_string(),
                "XMLInputFactory".to_string(),
                "TransformerFactory".to_string(),
                "SchemaFactory".to_string(),
            ],
            dangerous_arg: 0,
        });

        // C# SQL sinks
        self.sink_patterns.push(SinkPattern {
            name: "csharp_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "SqlCommand(".to_string(),
                "ExecuteReader(".to_string(),
                "ExecuteScalar(".to_string(),
                "ExecuteNonQuery(".to_string(),
                "FromSqlRaw(".to_string(),
                "ExecuteSqlRaw(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // C# command execution sinks
        self.sink_patterns.push(SinkPattern {
            name: "csharp_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "Process.Start(".to_string(),
                "ProcessStartInfo(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // C# file path sinks
        self.sink_patterns.push(SinkPattern {
            name: "csharp_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "File.ReadAllText(".to_string(),
                "File.WriteAllText(".to_string(),
                "File.Open(".to_string(),
                "FileStream(".to_string(),
                "StreamReader(".to_string(),
                "StreamWriter(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // C# deserialization sinks
        self.sink_patterns.push(SinkPattern {
            name: "csharp_deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "BinaryFormatter(".to_string(),
                "Deserialize(".to_string(),
                "JsonConvert.DeserializeObject(".to_string(),
                "XmlSerializer(".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Ruby SQL sinks
        self.sink_patterns.push(SinkPattern {
            name: "ruby_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                ".execute(".to_string(),
                ".exec_query(".to_string(),
                ".find_by_sql(".to_string(),
                ".where(".to_string(),
                "ActiveRecord::Base.connection".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Ruby command execution sinks
        self.sink_patterns.push(SinkPattern {
            name: "ruby_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                "system(".to_string(),
                "exec(".to_string(),
                "`".to_string(), // backticks
                "%x(".to_string(),
                "IO.popen(".to_string(),
                "Open3.".to_string(),
            ],
            dangerous_arg: 0,
        });

        // Ruby eval sinks
        self.sink_patterns.push(SinkPattern {
            name: "ruby_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                "eval(".to_string(),
                "instance_eval(".to_string(),
                "class_eval(".to_string(),
                "module_eval(".to_string(),
            ],
            dangerous_arg: 0,
        });
    }

    fn load_sanitizer_patterns(&mut self) {
        // SQL sanitizers (parameterized queries)
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "parameterized_query".to_string(),
            function_patterns: vec![
                "execute(?, ".to_string(),
                "execute(%s".to_string(),
                "query($".to_string(),
                "prepared".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        });

        // HTML escaping sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "html_escape".to_string(),
            function_patterns: vec![
                "escape(".to_string(),
                "html.escape".to_string(),
                "encodeURIComponent".to_string(),
                "htmlspecialchars".to_string(),
                "sanitize".to_string(),
                "DOMPurify".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        });

        // Path sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "path_sanitize".to_string(),
            function_patterns: vec![
                "os.path.basename".to_string(),
                "path.basename".to_string(),
                "realpath".to_string(),
                "normpath".to_string(),
                "secure_filename".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        });

        // Command sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "shell_escape".to_string(),
            function_patterns: vec![
                "shlex.quote".to_string(),
                "shellescape".to_string(),
                "escapeshellarg".to_string(),
            ],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["python".to_string()],
        });

        // PHP sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "php_sql_sanitize".to_string(),
            function_patterns: vec![
                "prepare(".to_string(),
                "bindParam(".to_string(),
                "bindValue(".to_string(),
                "mysql_real_escape_string(".to_string(),
                "mysqli_real_escape_string(".to_string(),
                "pg_escape_string(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["php".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "php_html_sanitize".to_string(),
            function_patterns: vec![
                "htmlspecialchars(".to_string(),
                "htmlentities(".to_string(),
                "strip_tags(".to_string(),
                "filter_var(".to_string(),
                "filter_input(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["php".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "php_path_sanitize".to_string(),
            function_patterns: vec!["basename(".to_string(), "realpath(".to_string()],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["php".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "php_command_sanitize".to_string(),
            function_patterns: vec!["escapeshellarg(".to_string(), "escapeshellcmd(".to_string()],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["php".to_string()],
        });

        // Java sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "java_sql_sanitize".to_string(),
            function_patterns: vec![
                "PreparedStatement".to_string(),
                "setString(".to_string(),
                "setInt(".to_string(),
                "setParameter(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "java_html_sanitize".to_string(),
            function_patterns: vec![
                "ESAPI.encoder()".to_string(),
                "HtmlUtils.htmlEscape".to_string(),
                "StringEscapeUtils.escapeHtml".to_string(),
                "Encode.forHtml".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "java_path_sanitize".to_string(),
            function_patterns: vec![
                "FilenameUtils.getName".to_string(),
                "normalize(".to_string(),
                "getCanonicalPath(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        });

        // C# sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "csharp_sql_sanitize".to_string(),
            function_patterns: vec![
                "SqlParameter".to_string(),
                "AddWithValue(".to_string(),
                "Parameters.Add(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["csharp".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "csharp_html_sanitize".to_string(),
            function_patterns: vec![
                "HttpUtility.HtmlEncode".to_string(),
                "WebUtility.HtmlEncode".to_string(),
                "AntiXssEncoder".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["csharp".to_string()],
        });

        // Ruby sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "ruby_sql_sanitize".to_string(),
            function_patterns: vec![
                "sanitize_sql".to_string(),
                "quote(".to_string(),
                "prepare(".to_string(),
                "where(".to_string(), // when used with hash/array params
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["ruby".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "ruby_html_sanitize".to_string(),
            function_patterns: vec![
                "h(".to_string(),
                "html_escape(".to_string(),
                "sanitize(".to_string(),
                "ERB::Util.html_escape".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["ruby".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "ruby_command_sanitize".to_string(),
            function_patterns: vec!["Shellwords.escape(".to_string(), "shellescape(".to_string()],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["ruby".to_string()],
        });

        // Rust sanitizers
        self.sanitizer_patterns.push(SanitizerPattern {
            name: "rust_path_sanitize".to_string(),
            function_patterns: vec![
                "canonicalize(".to_string(),
                "validate_path(".to_string(),
                ".canonicalize()".to_string(),
                "Path::new(".to_string(),
                ".file_name()".to_string(),
                ".file_stem()".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["rust".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "rust_sql_sanitize".to_string(),
            function_patterns: vec![
                "query_as!".to_string(),
                "query!".to_string(),
                ".bind(".to_string(),
                "execute!".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["rust".to_string()],
        });

        self.sanitizer_patterns.push(SanitizerPattern {
            name: "rust_html_sanitize".to_string(),
            function_patterns: vec![
                "html_escape(".to_string(),
                "Escape::new(".to_string(),
                "encode(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["rust".to_string()],
        });
    }

    /// Analyze code for taint flows
    pub fn analyze_code(&self, source_code: &str, file_path: &str) -> TaintAnalysisResult {
        let start_time = std::time::Instant::now();
        let mut result = TaintAnalysisResult::new(file_path);

        // Find sources
        result.sources = self.find_sources(source_code, file_path);
        result.stats.sources_found = result.sources.len();

        // Find sinks
        result.sinks = self.find_sinks(source_code, file_path);
        result.stats.sinks_found = result.sinks.len();

        // Find flows from sources to sinks
        result.flows = self.find_flows(source_code, file_path, &result.sources, &result.sinks);
        result.stats.flows_found = result.flows.len();

        // Separate vulnerabilities from sanitized flows
        for flow in &result.flows {
            if !flow.is_sanitized && flow.vulnerability.is_some() {
                result.vulnerabilities.push(flow.clone());
            } else if flow.is_sanitized {
                result.stats.sanitized_flows += 1;
            }
        }
        result.stats.vulnerabilities_found = result.vulnerabilities.len();

        result.stats.files_analyzed = 1;
        result.stats.analysis_time_ms = start_time.elapsed().as_millis() as u64;

        result
    }

    /// Find taint sources in code
    fn find_sources(&self, source_code: &str, file_path: &str) -> Vec<TaintSource> {
        let mut sources = Vec::new();
        let mut id_counter = 0;

        for (line_num, line) in source_code.lines().enumerate() {
            let line_num = line_num + 1; // 1-indexed

            for pattern in &self.source_patterns {
                // Check if pattern applies to this language
                if !pattern.languages.contains(&self.language) && !pattern.languages.is_empty() {
                    continue;
                }

                // Check property patterns
                for prop_pattern in &pattern.property_patterns {
                    if line.contains(prop_pattern) {
                        // Try to extract variable name
                        let variable = self
                            .extract_variable_from_assignment(line)
                            .unwrap_or_else(|| format!("var_{}", id_counter));

                        sources.push(TaintSource {
                            id: format!("src_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            variable,
                            code: line.trim().chars().take(100).collect(),
                            confidence: pattern.confidence,
                        });
                        id_counter += 1;
                    }
                }

                // Check function patterns
                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        let variable = self
                            .extract_variable_from_assignment(line)
                            .unwrap_or_else(|| format!("var_{}", id_counter));

                        sources.push(TaintSource {
                            id: format!("src_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            variable,
                            code: line.trim().chars().take(100).collect(),
                            confidence: pattern.confidence,
                        });
                        id_counter += 1;
                    }
                }
            }
        }

        sources
    }

    /// Find taint sinks in code
    fn find_sinks(&self, source_code: &str, file_path: &str) -> Vec<TaintSink> {
        let mut sinks = Vec::new();
        let mut id_counter = 0;

        for (line_num, line) in source_code.lines().enumerate() {
            let line_num = line_num + 1;

            for pattern in &self.sink_patterns {
                if !pattern.languages.contains(&self.language) && !pattern.languages.is_empty() {
                    continue;
                }

                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        sinks.push(TaintSink {
                            id: format!("sink_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            function: func_pattern.trim_end_matches('(').to_string(),
                            code: line.trim().chars().take(100).collect(),
                            dangerous_arg: pattern.dangerous_arg,
                        });
                        id_counter += 1;
                    }
                }
            }
        }

        sinks
    }

    /// Find taint flows from sources to sinks
    fn find_flows(
        &self,
        source_code: &str,
        file_path: &str,
        sources: &[TaintSource],
        sinks: &[TaintSink],
    ) -> Vec<TaintFlow> {
        let mut flows = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();
        let mut flow_id = 0;

        for source in sources {
            // Track tainted variables
            let mut tainted_vars: HashSet<String> = HashSet::new();
            tainted_vars.insert(source.variable.clone());

            // Simple forward propagation through code
            for line_num in source.line..=lines.len() {
                let line_idx = line_num - 1;
                if line_idx >= lines.len() {
                    break;
                }
                let line = lines[line_idx];

                // Check for taint propagation (assignments)
                if let Some((lhs, rhs)) = self.parse_assignment(line) {
                    // If RHS contains tainted var, LHS becomes tainted
                    for tainted_var in tainted_vars.clone() {
                        if rhs.contains(&tainted_var) {
                            tainted_vars.insert(lhs.clone());
                        }
                    }
                }

                // Check if any tainted variable reaches a sink
                for sink in sinks {
                    if sink.line == line_num {
                        // Check if any tainted var is in the sink code
                        for tainted_var in &tainted_vars {
                            if sink.code.contains(tainted_var) {
                                // Check for sanitizers
                                let is_sanitized = self.check_sanitization(
                                    &lines,
                                    source.line,
                                    sink.line,
                                    tainted_var,
                                    &sink.kind,
                                );

                                let vulnerability = if is_sanitized {
                                    None
                                } else {
                                    Some(sink.kind.vulnerability_type())
                                };

                                let severity = vulnerability.as_ref().map(|v| v.default_severity());

                                let path =
                                    self.build_path(&lines, source, sink, tainted_var, file_path);

                                flows.push(TaintFlow {
                                    id: format!("flow_{}", flow_id),
                                    source: source.clone(),
                                    sink: sink.clone(),
                                    path,
                                    sanitizers: Vec::new(),
                                    vulnerability,
                                    severity,
                                    confidence: source.confidence,
                                    is_sanitized,
                                });
                                flow_id += 1;
                            }
                        }
                    }
                }
            }
        }

        flows
    }

    /// Check if a flow is sanitized
    fn check_sanitization(
        &self,
        lines: &[&str],
        source_line: usize,
        sink_line: usize,
        _variable: &str,
        sink_kind: &SinkKind,
    ) -> bool {
        for line_num in source_line..sink_line {
            if line_num > 0 && line_num <= lines.len() {
                let line = lines[line_num - 1];

                for pattern in &self.sanitizer_patterns {
                    if pattern.sanitizes_for.contains(sink_kind) {
                        for func_pattern in &pattern.function_patterns {
                            if line.contains(func_pattern) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Build the path from source to sink
    fn build_path(
        &self,
        lines: &[&str],
        source: &TaintSource,
        sink: &TaintSink,
        variable: &str,
        file_path: &str,
    ) -> Vec<TaintStep> {
        let mut path = Vec::new();

        // Add source
        path.push(TaintStep {
            file_path: file_path.to_string(),
            line: source.line,
            code: source.code.clone(),
            variable: source.variable.clone(),
            operation: TaintOperation::Source,
        });

        // Add intermediate steps where variable appears
        for line_num in (source.line + 1)..sink.line {
            if line_num > 0 && line_num <= lines.len() {
                let line = lines[line_num - 1];
                if line.contains(variable) {
                    let operation = if line.contains('=') {
                        TaintOperation::Assignment
                    } else if line.contains('(') {
                        TaintOperation::FunctionCall {
                            function: self.extract_function_name(line).unwrap_or_default(),
                        }
                    } else {
                        TaintOperation::Assignment
                    };

                    path.push(TaintStep {
                        file_path: file_path.to_string(),
                        line: line_num,
                        code: line.trim().chars().take(100).collect(),
                        variable: variable.to_string(),
                        operation,
                    });
                }
            }
        }

        // Add sink
        path.push(TaintStep {
            file_path: file_path.to_string(),
            line: sink.line,
            code: sink.code.clone(),
            variable: variable.to_string(),
            operation: TaintOperation::Sink,
        });

        path
    }

    /// Extract variable name from assignment
    fn extract_variable_from_assignment(&self, line: &str) -> Option<String> {
        // Handle various assignment patterns
        let line = line.trim();

        // Python/JS: var = ...
        if let Some(eq_pos) = line.find('=') {
            if !line[..eq_pos].contains("==") && !line[..eq_pos].contains("!=") {
                let lhs = line[..eq_pos].trim();
                // Remove 'let', 'const', 'var', etc.
                let lhs = lhs
                    .trim_start_matches("let ")
                    .trim_start_matches("const ")
                    .trim_start_matches("var ")
                    .trim_start_matches("mut ")
                    .trim();
                // Get the variable name (first identifier)
                let var_name: String = lhs
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !var_name.is_empty() {
                    return Some(var_name);
                }
            }
        }

        None
    }

    /// Parse an assignment statement
    fn parse_assignment(&self, line: &str) -> Option<(String, String)> {
        let line = line.trim();

        if let Some(eq_pos) = line.find('=') {
            // Skip == and !=
            if eq_pos > 0 {
                let before = line.chars().nth(eq_pos.saturating_sub(1));
                let after = line.chars().nth(eq_pos + 1);
                if before == Some('=') || before == Some('!') || after == Some('=') {
                    return None;
                }
            }

            let lhs = line[..eq_pos].trim();
            let rhs = line[eq_pos + 1..].trim();

            // Clean up LHS
            let lhs = lhs
                .trim_start_matches("let ")
                .trim_start_matches("const ")
                .trim_start_matches("var ")
                .trim_start_matches("mut ")
                .trim();

            let var_name: String = lhs
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();

            if !var_name.is_empty() {
                return Some((var_name, rhs.to_string()));
            }
        }

        None
    }

    /// Extract function name from a line
    fn extract_function_name(&self, line: &str) -> Option<String> {
        // Look for pattern: name(
        if let Some(paren_pos) = line.find('(') {
            let before_paren = &line[..paren_pos];
            // Get the last identifier before (
            let name: String = before_paren
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect::<String>()
                .chars()
                .rev()
                .collect();

            if !name.is_empty() {
                return Some(name);
            }
        }
        None
    }
}

/// Convenience function to analyze Python code
pub fn analyze_python(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("python");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze JavaScript code
pub fn analyze_javascript(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("javascript");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze TypeScript code
pub fn analyze_typescript(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("typescript");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze Rust code
pub fn analyze_rust(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("rust");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze Go code
pub fn analyze_go(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("go");
    analyzer.analyze_code(source_code, file_path)
}

/// Detect language from file extension
pub fn detect_language(file_path: &str) -> &'static str {
    if file_path.ends_with(".py") {
        "python"
    } else if file_path.ends_with(".js") {
        "javascript"
    } else if file_path.ends_with(".ts") || file_path.ends_with(".tsx") {
        "typescript"
    } else if file_path.ends_with(".rs") {
        "rust"
    } else if file_path.ends_with(".go") {
        "go"
    } else if file_path.ends_with(".java") {
        "java"
    } else if file_path.ends_with(".c") || file_path.ends_with(".h") {
        "c"
    } else if file_path.ends_with(".cpp") || file_path.ends_with(".hpp") {
        "cpp"
    } else if file_path.ends_with(".cs") {
        "csharp"
    } else if file_path.ends_with(".php") {
        "php"
    } else if file_path.ends_with(".rb") {
        "ruby"
    } else if file_path.ends_with(".kt") || file_path.ends_with(".kts") {
        "kotlin"
    } else {
        "unknown"
    }
}

/// Analyze code with auto-detected language
pub fn analyze_code(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let language = detect_language(file_path);
    let analyzer = TaintAnalyzer::new(language);
    analyzer.analyze_code(source_code, file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_vulnerability_cwe() {
        assert_eq!(VulnerabilityKind::SqlInjection.cwe_id(), Some("CWE-89"));
        assert_eq!(VulnerabilityKind::Xss.cwe_id(), Some("CWE-79"));
        assert_eq!(VulnerabilityKind::CommandInjection.cwe_id(), Some("CWE-78"));
    }

    #[test]
    fn test_vulnerability_owasp() {
        assert!(VulnerabilityKind::SqlInjection.owasp_category().is_some());
        assert!(VulnerabilityKind::Xss.owasp_category().is_some());
    }

    #[test]
    fn test_source_kind_display() {
        let source = SourceKind::UserInput {
            input_type: "http".to_string(),
        };
        assert!(source.display_name().contains("User Input"));
    }

    #[test]
    fn test_sink_kind_display() {
        assert_eq!(SinkKind::SqlQuery.display_name(), "SQL Query");
        assert_eq!(SinkKind::CommandExec.display_name(), "Command Execution");
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("test.py"), "python");
        assert_eq!(detect_language("test.js"), "javascript");
        assert_eq!(detect_language("test.ts"), "typescript");
        assert_eq!(detect_language("test.rs"), "rust");
        assert_eq!(detect_language("test.go"), "go");
    }

    #[test]
    fn test_analyze_python_sqli() {
        let code = r#"
def search(request):
    query = request.GET['q']
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
"#;
        let result = analyze_python(code, "test.py");

        assert!(!result.sources.is_empty());
        assert!(!result.sinks.is_empty());
    }

    #[test]
    fn test_analyze_js_xss() {
        let code = r#"
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results for: ${query}</h1>`);
});
"#;
        let result = analyze_javascript(code, "test.js");

        assert!(!result.sources.is_empty());
    }

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new("python");
        assert!(!analyzer.source_patterns.is_empty());
        assert!(!analyzer.sink_patterns.is_empty());
        assert!(!analyzer.sanitizer_patterns.is_empty());
    }

    #[test]
    fn test_extract_variable_from_assignment() {
        let analyzer = TaintAnalyzer::new("python");

        assert_eq!(
            analyzer.extract_variable_from_assignment("x = request.GET['q']"),
            Some("x".to_string())
        );

        assert_eq!(
            analyzer.extract_variable_from_assignment("let data = req.body"),
            Some("data".to_string())
        );

        assert_eq!(
            analyzer.extract_variable_from_assignment("const value = input"),
            Some("value".to_string())
        );
    }

    #[test]
    fn test_parse_assignment() {
        let analyzer = TaintAnalyzer::new("python");

        let result = analyzer.parse_assignment("x = y + z");
        assert!(result.is_some());
        let (lhs, rhs) = result.unwrap();
        assert_eq!(lhs, "x");
        assert!(rhs.contains("y"));

        // Should not parse equality check
        assert!(analyzer.parse_assignment("x == y").is_none());
        assert!(analyzer.parse_assignment("x != y").is_none());
    }

    #[test]
    fn test_taint_flow_markdown() {
        let flow = TaintFlow {
            id: "flow_1".to_string(),
            source: TaintSource {
                id: "src_1".to_string(),
                kind: SourceKind::UserInput {
                    input_type: "http".to_string(),
                },
                file_path: "test.py".to_string(),
                line: 1,
                variable: "query".to_string(),
                code: "query = request.GET['q']".to_string(),
                confidence: Confidence::High,
            },
            sink: TaintSink {
                id: "sink_1".to_string(),
                kind: SinkKind::SqlQuery,
                file_path: "test.py".to_string(),
                line: 2,
                function: "execute".to_string(),
                code: "cursor.execute(query)".to_string(),
                dangerous_arg: 0,
            },
            path: Vec::new(),
            sanitizers: Vec::new(),
            vulnerability: Some(VulnerabilityKind::SqlInjection),
            severity: Some(Severity::Critical),
            confidence: Confidence::High,
            is_sanitized: false,
        };

        let md = flow.to_markdown();
        assert!(md.contains("SQL Injection"));
        assert!(md.contains("CWE-89"));
    }

    #[test]
    fn test_taint_analysis_result_markdown() {
        let result = TaintAnalysisResult::new("test.py");
        let md = result.to_markdown();

        assert!(md.contains("Taint Analysis"));
        assert!(md.contains("test.py"));
        assert!(md.contains("Summary"));
    }

    #[test]
    fn test_sanitization_detection() {
        let code = r#"
def search(request):
    query = request.GET['q']
    safe_query = escape(query)
    res.send(safe_query)
"#;
        let analyzer = TaintAnalyzer::new("python");
        let lines: Vec<&str> = code.lines().collect();

        // Check that escape() is detected as sanitizer for HTML output
        let is_sanitized = analyzer.check_sanitization(
            &lines,
            3, // source line
            5, // sink line
            "query",
            &SinkKind::HtmlOutput,
        );

        assert!(is_sanitized);
    }

    #[test]
    fn test_source_patterns_loaded() {
        let analyzer = TaintAnalyzer::new("python");

        // Should have Flask patterns
        assert!(analyzer
            .source_patterns
            .iter()
            .any(|p| p.name == "flask_request"));
        // Should have Django patterns
        assert!(analyzer
            .source_patterns
            .iter()
            .any(|p| p.name == "django_request"));
    }

    #[test]
    fn test_sink_patterns_loaded() {
        let analyzer = TaintAnalyzer::new("python");

        // Should have SQL patterns
        assert!(analyzer
            .sink_patterns
            .iter()
            .any(|p| p.kind == SinkKind::SqlQuery));
        // Should have command exec patterns
        assert!(analyzer
            .sink_patterns
            .iter()
            .any(|p| p.kind == SinkKind::CommandExec));
    }

    #[test]
    fn test_sanitizer_patterns_loaded() {
        let analyzer = TaintAnalyzer::new("python");

        // Should have parameterized query patterns
        assert!(analyzer
            .sanitizer_patterns
            .iter()
            .any(|p| p.name == "parameterized_query"));
        // Should have HTML escape patterns
        assert!(analyzer
            .sanitizer_patterns
            .iter()
            .any(|p| p.name == "html_escape"));
    }

    #[test]
    fn test_command_injection_detection() {
        let code = r#"
import subprocess
def run(request):
    cmd = request.GET['cmd']
    subprocess.call(cmd, shell=True)
"#;
        let result = analyze_python(code, "test.py");

        // Should find source
        assert!(!result.sources.is_empty());
        // Should find command execution sink
        assert!(result.sinks.iter().any(|s| s.kind == SinkKind::CommandExec));
    }

    #[test]
    fn test_flow_building() {
        let code = r#"
query = request.GET['q']
data = process(query)
cursor.execute(data)
"#;
        let result = analyze_python(code, "test.py");

        if !result.flows.is_empty() {
            let flow = &result.flows[0];
            // Path should have source, intermediate steps, and sink
            assert!(!flow.path.is_empty());
        }
    }

    #[test]
    fn test_extract_function_name() {
        let analyzer = TaintAnalyzer::new("python");

        assert_eq!(
            analyzer.extract_function_name("cursor.execute(query)"),
            Some("cursor.execute".to_string())
        );

        assert_eq!(
            analyzer.extract_function_name("subprocess.call(cmd)"),
            Some("subprocess.call".to_string())
        );
    }

    #[test]
    fn test_multiple_sources_same_file() {
        let code = r#"
query1 = request.GET['q1']
query2 = request.POST['q2']
data = request.json['data']
"#;
        let result = analyze_python(code, "test.py");

        // Should find multiple sources
        assert!(result.sources.len() >= 2);
    }

    #[test]
    fn test_taint_stats() {
        let code = r#"
query = request.GET['q']
cursor.execute(query)
"#;
        let result = analyze_python(code, "test.py");

        assert_eq!(result.stats.files_analyzed, 1);
        assert!(result.stats.analysis_time_ms < 1000); // Should be fast
    }

    #[test]
    fn test_go_analysis() {
        let code = r#"
func handler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    db.Query("SELECT * FROM users WHERE name = '" + query + "'")
}
"#;
        let result = analyze_go(code, "test.go");

        // Should detect sources or sinks in Go code
        assert!(!result.sources.is_empty() || !result.sinks.is_empty());
    }

    #[test]
    fn test_rust_analysis() {
        let code = r#"
async fn handler(query: web::Query<SearchParams>) -> impl Responder {
    let user_input = query.q.clone();
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", user_input))
}
"#;
        let result = analyze_rust(code, "test.rs");

        // Should work without panicking
        assert_eq!(result.stats.files_analyzed, 1);
    }

    #[test]
    fn test_typescript_analysis() {
        let code = r#"
app.get('/search', (req: Request, res: Response) => {
    const query = req.query.q as string;
    res.send(`<div>${query}</div>`);
});
"#;
        let result = analyze_typescript(code, "test.ts");

        // Should detect sources
        assert!(!result.sources.is_empty());
    }
}
