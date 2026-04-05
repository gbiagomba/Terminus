#[derive(Debug, PartialEq)]
pub enum Command {
    Open(i64),
    Replay(i64),
    FilterStatus(u16),
    FilterExploit(String),
    Search(String),
    Tag(i64, String),
    Help,
    Quit,
    Unknown(String),
}

/// Parse a command string into a `Command` enum.
pub fn parse_command(input: &str) -> Command {
    let input = input.trim();

    if input == "q" || input == ":quit" || input == ":q" {
        return Command::Quit;
    }

    if input == ":help" || input == "help" {
        return Command::Help;
    }

    if let Some(rest) = input.strip_prefix(":open ") {
        if let Ok(id) = rest.trim().parse::<i64>() {
            return Command::Open(id);
        }
    }

    if let Some(rest) = input.strip_prefix(":replay ") {
        if let Ok(id) = rest.trim().parse::<i64>() {
            return Command::Replay(id);
        }
    }

    if let Some(rest) = input.strip_prefix(":filter status ") {
        if let Ok(code) = rest.trim().parse::<u16>() {
            return Command::FilterStatus(code);
        }
    }

    if let Some(rest) = input.strip_prefix(":filter exploit ") {
        return Command::FilterExploit(rest.trim().to_string());
    }

    if let Some(rest) = input.strip_prefix(":search ") {
        return Command::Search(rest.trim().to_string());
    }

    if let Some(rest) = input.strip_prefix(":tag ") {
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() == 2 {
            if let Ok(id) = parts[0].trim().parse::<i64>() {
                return Command::Tag(id, parts[1].trim().to_string());
            }
        }
    }

    Command::Unknown(input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_command() {
        let cmd = parse_command(":open 42");
        assert!(matches!(cmd, Command::Open(42)));
    }

    #[test]
    fn test_parse_replay_command() {
        let cmd = parse_command(":replay 42");
        assert!(matches!(cmd, Command::Replay(42)));
    }

    #[test]
    fn test_parse_filter_status() {
        let cmd = parse_command(":filter status 200");
        assert!(matches!(cmd, Command::FilterStatus(200)));
    }

    #[test]
    fn test_parse_quit() {
        let cmd = parse_command(":quit");
        assert!(matches!(cmd, Command::Quit));
        let cmd2 = parse_command("q");
        assert!(matches!(cmd2, Command::Quit));
    }

    #[test]
    fn test_parse_unknown() {
        let cmd = parse_command("garbage input");
        assert!(matches!(cmd, Command::Unknown(_)));
    }
}
