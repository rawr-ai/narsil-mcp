/// Editor detection and preset mapping
///
/// Maps MCP client names to appropriate tool presets based on editor capabilities
/// and performance characteristics.
use super::preset::Preset;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorType {
    ClaudeDesktop,
    ClaudeCode,
    Zed,
    VSCode,
    JetBrains,
}

impl fmt::Display for EditorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditorType::ClaudeDesktop => write!(f, "Claude Desktop"),
            EditorType::ClaudeCode => write!(f, "Claude Code"),
            EditorType::Zed => write!(f, "Zed"),
            EditorType::VSCode => write!(f, "VS Code"),
            EditorType::JetBrains => write!(f, "JetBrains IDEs"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EditorConfig {
    pub editor_type: EditorType,
    pub config_path: PathBuf,
    pub exists: bool,
}

/// Get the config file path for a specific editor
pub fn get_editor_config_path(editor: EditorType) -> PathBuf {
    match editor {
        EditorType::ClaudeDesktop => get_claude_desktop_config_path(),
        EditorType::ClaudeCode => get_claude_code_config_path(),
        EditorType::Zed => get_zed_config_path(),
        EditorType::VSCode => get_vscode_config_path(),
        EditorType::JetBrains => get_jetbrains_config_path(),
    }
}

/// Detect which editors have config files on this system
pub fn detect_available_editors() -> Vec<EditorConfig> {
    let mut editors = Vec::new();

    for editor_type in [
        EditorType::ClaudeDesktop,
        EditorType::ClaudeCode,
        EditorType::Zed,
        EditorType::VSCode,
        EditorType::JetBrains,
    ] {
        let config_path = get_editor_config_path(editor_type);
        let exists = config_path.exists();

        editors.push(EditorConfig {
            editor_type,
            config_path,
            exists,
        });
    }

    editors
}

fn get_claude_desktop_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json")
        } else {
            PathBuf::from("claude_desktop_config.json")
        }
    }

    #[cfg(target_os = "windows")]
    {
        use directories::ProjectDirs;
        if let Some(proj_dirs) = ProjectDirs::from("com", "Anthropic", "Claude") {
            proj_dirs.config_dir().join("claude_desktop_config.json")
        } else {
            PathBuf::from("claude_desktop_config.json")
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        use directories::ProjectDirs;
        if let Some(proj_dirs) = ProjectDirs::from("com", "Anthropic", "Claude") {
            proj_dirs.config_dir().join("claude_desktop_config.json")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home)
                .join(".config")
                .join("Claude")
                .join("claude_desktop_config.json")
        } else {
            PathBuf::from("claude_desktop_config.json")
        }
    }
}

fn get_claude_code_config_path() -> PathBuf {
    // Check HOME (Unix) or USERPROFILE (Windows)
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home)
            .join(".claude")
            .join("claude_code_config.json")
    } else {
        PathBuf::from("claude_code_config.json")
    }
}

fn get_zed_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use directories::ProjectDirs;
        if let Some(proj_dirs) = ProjectDirs::from("dev", "zed", "Zed") {
            proj_dirs.config_dir().join("settings.json")
        } else {
            PathBuf::from("settings.json")
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Zed uses ~/.config/zed on Unix-like systems
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home)
                .join(".config")
                .join("zed")
                .join("settings.json")
        } else {
            PathBuf::from("settings.json")
        }
    }
}

fn get_vscode_config_path() -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(".vscode")
        .join("mcp.json")
}

fn get_jetbrains_config_path() -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(".idea")
        .join("mcp.json")
}

/// Map an editor name to a preset
///
/// # Arguments
/// * `editor_name` - The name from MCP clientInfo (case-insensitive)
///
/// # Returns
/// * `Some(Preset)` - If the editor is recognized
/// * `None` - If the editor is unknown (caller should use Full preset)
///
/// # Supported Editors
/// - **VS Code / Code**: Balanced preset (40-50 tools)
/// - **Zed**: Minimal preset (20-30 tools, optimized for speed)
/// - **Claude Desktop / Claude**: Full preset (all tools)
/// - **Unknown**: Full preset by default (conservative choice)
pub fn get_editor_preset(editor_name: &str) -> Option<Preset> {
    let normalized = editor_name.trim().to_lowercase();

    match normalized.as_str() {
        // VS Code and variants
        "vscode" | "code" | "visual studio code" => Some(Preset::Balanced),

        // Zed editor - optimized for speed
        "zed" => Some(Preset::Minimal),

        // Claude Desktop - full capabilities
        "claude-desktop" | "claude" | "claude.ai" => Some(Preset::Full),

        // JetBrains IDEs - balanced
        "intellij" | "idea" | "pycharm" | "webstorm" | "rustrover" | "clion" | "goland"
        | "phpstorm" | "rider" => Some(Preset::Balanced),

        // Vim/Neovim - minimal for speed
        "vim" | "nvim" | "neovim" => Some(Preset::Minimal),

        // Emacs - balanced
        "emacs" => Some(Preset::Balanced),

        // Sublime Text - balanced
        "sublime" | "sublime text" | "subl" => Some(Preset::Balanced),

        // Cursor - VS Code fork
        "cursor" => Some(Preset::Balanced),

        // Unknown editor - return None to signal "use full preset"
        _ => None,
    }
}

/// Get the preset for an editor, with fallback to Full
///
/// This is a convenience wrapper around `get_editor_preset` that always
/// returns a preset (never None).
pub fn get_editor_preset_or_full(editor_name: &str) -> Preset {
    get_editor_preset(editor_name).unwrap_or(Preset::Full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vscode_detection() {
        assert_eq!(
            get_editor_preset("vscode"),
            Some(Preset::Balanced),
            "vscode should map to Balanced"
        );
        assert_eq!(
            get_editor_preset("code"),
            Some(Preset::Balanced),
            "code should map to Balanced"
        );
        assert_eq!(
            get_editor_preset("visual studio code"),
            Some(Preset::Balanced)
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(get_editor_preset("VSCode"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("VSCODE"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("VsCode"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("Zed"), Some(Preset::Minimal));
        assert_eq!(get_editor_preset("ZED"), Some(Preset::Minimal));
    }

    #[test]
    fn test_zed_detection() {
        assert_eq!(
            get_editor_preset("zed"),
            Some(Preset::Minimal),
            "zed should map to Minimal"
        );
    }

    #[test]
    fn test_claude_detection() {
        assert_eq!(get_editor_preset("claude-desktop"), Some(Preset::Full));
        assert_eq!(get_editor_preset("claude"), Some(Preset::Full));
        assert_eq!(get_editor_preset("claude.ai"), Some(Preset::Full));
    }

    #[test]
    fn test_jetbrains_detection() {
        assert_eq!(get_editor_preset("intellij"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("idea"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("pycharm"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("webstorm"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("rustrover"), Some(Preset::Balanced));
    }

    #[test]
    fn test_vim_detection() {
        assert_eq!(get_editor_preset("vim"), Some(Preset::Minimal));
        assert_eq!(get_editor_preset("nvim"), Some(Preset::Minimal));
        assert_eq!(get_editor_preset("neovim"), Some(Preset::Minimal));
    }

    #[test]
    fn test_emacs_detection() {
        assert_eq!(get_editor_preset("emacs"), Some(Preset::Balanced));
    }

    #[test]
    fn test_sublime_detection() {
        assert_eq!(get_editor_preset("sublime"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("sublime text"), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("subl"), Some(Preset::Balanced));
    }

    #[test]
    fn test_cursor_detection() {
        assert_eq!(get_editor_preset("cursor"), Some(Preset::Balanced));
    }

    #[test]
    fn test_unknown_editor() {
        assert_eq!(get_editor_preset("unknown-editor"), None);
        assert_eq!(get_editor_preset("some-new-ide"), None);
        assert_eq!(get_editor_preset(""), None);
    }

    #[test]
    fn test_fallback_to_full() {
        assert_eq!(
            get_editor_preset_or_full("unknown"),
            Preset::Full,
            "Unknown editors should default to Full preset"
        );
    }

    #[test]
    fn test_whitespace_handling() {
        assert_eq!(get_editor_preset(" vscode "), Some(Preset::Balanced));
        assert_eq!(get_editor_preset("  zed  "), Some(Preset::Minimal));
    }
}
