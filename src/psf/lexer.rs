//! PSF Lexer - Tokenizes PSF files
//!
//! Converts PSF source code into a stream of tokens for parsing

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    At,                    // @
    Segment,              // SEGMENT
    Define,               // DEFINE
    Role,                 // ROLE
    Phase,                // PHASE
    Format,               // FORMAT
    Field,                // FIELD
    Semantic,             // SEMANTIC
    Encrypt,              // ENCRYPT
    From,                 // FROM
    Ptext,                // PTEXT
    Ctext,                // CTEXT
    Mac,                  // MAC

    // Semantic types
    FixedValue,           // FIXED_VALUE
    Length,               // LENGTH
    Payload,              // PAYLOAD
    Padding,              // PADDING
    CommandType,          // COMMAND_TYPE

    // Field types
    U1,                   // u1 (bit)
    U2,                   // u2 (2 bits)
    U4,                   // u4 (4 bits)
    U5,                   // u5 (5 bits)
    U7,                   // u7 (7 bits)
    U8,                   // u8
    U16,                  // u16
    U24,                  // u24
    U32,                  // u32
    U64,                  // u64
    Varint,               // varint

    // Symbols
    LeftBrace,            // {
    RightBrace,           // }
    LeftBracket,          // [
    RightBracket,         // ]
    LeftParen,            // (
    RightParen,           // )
    Semicolon,            // ;
    Colon,                // :
    Comma,                // ,
    Dot,                  // .
    Equals,               // =
    Star,                 // *
    Plus,                 // +
    Minus,                // -

    // Literals
    Identifier(String),   // abc, Foo_Bar123
    Number(u64),          // 123, 0x17
    String(String),       // "hello"
    Char(char),           // 'a'

    // Special
    Newline,
    Eof,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Identifier(s) => write!(f, "Identifier({})", s),
            Token::Number(n) => write!(f, "Number({})", n),
            Token::String(s) => write!(f, "String(\"{}\")", s),
            Token::Char(c) => write!(f, "Char('{}')", c),
            other => write!(f, "{:?}", other),
        }
    }
}

pub struct Lexer {
    input: Vec<char>,
    position: usize,
}

impl Lexer {
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();

        while !self.is_eof() {
            self.skip_whitespace_except_newline();

            if self.is_eof() {
                break;
            }

            // Skip comments
            if self.current() == '/' && self.peek() == Some('/') {
                self.skip_line_comment();
                continue;
            }

            if self.current() == '/' && self.peek() == Some('*') {
                self.skip_block_comment();
                continue;
            }

            // Skip # comments (hash comments)
            if self.current() == '#' {
                self.skip_line_comment();
                continue;
            }

            // Newlines
            if self.current() == '\n' {
                tokens.push(Token::Newline);
                self.advance();
                continue;
            }

            // Symbols
            let token = match self.current() {
                '@' => {
                    self.advance();
                    Token::At
                }
                '{' => {
                    self.advance();
                    Token::LeftBrace
                }
                '}' => {
                    self.advance();
                    Token::RightBrace
                }
                '[' => {
                    self.advance();
                    Token::LeftBracket
                }
                ']' => {
                    self.advance();
                    Token::RightBracket
                }
                '(' => {
                    self.advance();
                    Token::LeftParen
                }
                ')' => {
                    self.advance();
                    Token::RightParen
                }
                ';' => {
                    self.advance();
                    Token::Semicolon
                }
                ':' => {
                    self.advance();
                    Token::Colon
                }
                ',' => {
                    self.advance();
                    Token::Comma
                }
                '.' => {
                    self.advance();
                    Token::Dot
                }
                '=' => {
                    self.advance();
                    Token::Equals
                }
                '*' => {
                    self.advance();
                    Token::Star
                }
                '+' => {
                    self.advance();
                    Token::Plus
                }
                '-' => {
                    self.advance();
                    Token::Minus
                }
                '"' => self.read_string()?,
                '\'' => self.read_char()?,
                '0'..='9' => self.read_number()?,
                'a'..='z' | 'A'..='Z' | '_' => self.read_identifier_or_keyword(),
                c => return Err(format!("Unexpected character: '{}'", c)),
            };

            tokens.push(token);
        }

        tokens.push(Token::Eof);
        Ok(tokens)
    }

    fn current(&self) -> char {
        self.input[self.position]
    }

    fn peek(&self) -> Option<char> {
        if self.position + 1 < self.input.len() {
            Some(self.input[self.position + 1])
        } else {
            None
        }
    }

    fn advance(&mut self) {
        self.position += 1;
    }

    fn is_eof(&self) -> bool {
        self.position >= self.input.len()
    }

    fn skip_whitespace_except_newline(&mut self) {
        while !self.is_eof() && matches!(self.current(), ' ' | '\t' | '\r') {
            self.advance();
        }
    }

    fn skip_line_comment(&mut self) {
        while !self.is_eof() && self.current() != '\n' {
            self.advance();
        }
    }

    fn skip_block_comment(&mut self) {
        self.advance(); // skip '/'
        self.advance(); // skip '*'

        while !self.is_eof() {
            if self.current() == '*' && self.peek() == Some('/') {
                self.advance(); // skip '*'
                self.advance(); // skip '/'
                break;
            }
            self.advance();
        }
    }

    fn read_string(&mut self) -> Result<Token, String> {
        self.advance(); // skip opening "

        let mut s = String::new();
        while !self.is_eof() && self.current() != '"' {
            if self.current() == '\\' {
                self.advance();
                if self.is_eof() {
                    return Err("Unterminated string".to_string());
                }
                // Simple escape handling
                match self.current() {
                    'n' => s.push('\n'),
                    't' => s.push('\t'),
                    'r' => s.push('\r'),
                    '\\' => s.push('\\'),
                    '"' => s.push('"'),
                    c => s.push(c),
                }
            } else {
                s.push(self.current());
            }
            self.advance();
        }

        if self.is_eof() {
            return Err("Unterminated string".to_string());
        }

        self.advance(); // skip closing "
        Ok(Token::String(s))
    }

    fn read_char(&mut self) -> Result<Token, String> {
        self.advance(); // skip opening '

        if self.is_eof() {
            return Err("Unterminated character literal".to_string());
        }

        let c = if self.current() == '\\' {
            self.advance();
            if self.is_eof() {
                return Err("Unterminated character literal".to_string());
            }
            // Simple escape handling
            match self.current() {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                '\'' => '\'',
                c => c,
            }
        } else {
            self.current()
        };

        self.advance();

        if self.is_eof() || self.current() != '\'' {
            return Err("Unterminated character literal".to_string());
        }

        self.advance(); // skip closing '
        Ok(Token::Char(c))
    }

    fn read_number(&mut self) -> Result<Token, String> {
        let mut s = String::new();

        // Check for hex
        if self.current() == '0' && self.peek() == Some('x') {
            self.advance(); // skip '0'
            self.advance(); // skip 'x'

            while !self.is_eof() && self.current().is_ascii_hexdigit() {
                s.push(self.current());
                self.advance();
            }

            // If the hex string is too long for u64 (>16 hex digits), treat as string
            if s.len() > 16 {
                return Ok(Token::String(format!("0x{}", s)));
            }

            let value = u64::from_str_radix(&s, 16)
                .map_err(|e| format!("Invalid hex number: {}", e))?;
            return Ok(Token::Number(value));
        }

        // Decimal
        while !self.is_eof() && self.current().is_ascii_digit() {
            s.push(self.current());
            self.advance();
        }

        let value = s.parse::<u64>()
            .map_err(|e| format!("Invalid number: {}", e))?;
        Ok(Token::Number(value))
    }

    fn read_identifier_or_keyword(&mut self) -> Token {
        let mut s = String::new();

        while !self.is_eof() && (self.current().is_alphanumeric() || self.current() == '_') {
            s.push(self.current());
            self.advance();
        }

        // Check for keywords
        match s.as_str() {
            "SEGMENT" => Token::Segment,
            "DEFINE" => Token::Define,
            "ROLE" => Token::Role,
            "PHASE" => Token::Phase,
            "FORMAT" => Token::Format,
            "FIELD" => Token::Field,
            "SEMANTIC" => Token::Semantic,
            "ENCRYPT" => Token::Encrypt,
            "FROM" => Token::From,
            "PTEXT" => Token::Ptext,
            "CTEXT" => Token::Ctext,
            "MAC" => Token::Mac,
            "FIXED_VALUE" => Token::FixedValue,
            "LENGTH" => Token::Length,
            "PAYLOAD" => Token::Payload,
            "PADDING" => Token::Padding,
            "COMMAND_TYPE" => Token::CommandType,
            "u1" => Token::U1,
            "u2" => Token::U2,
            "u4" => Token::U4,
            "u5" => Token::U5,
            "u7" => Token::U7,
            "u8" => Token::U8,
            "u16" => Token::U16,
            "u24" => Token::U24,
            "u32" => Token::U32,
            "u64" => Token::U64,
            "varint" => Token::Varint,
            _ => Token::Identifier(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tokens() {
        let input = "@ DEFINE { } ; : = u8 u16";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0], Token::At);
        assert_eq!(tokens[1], Token::Define);
        assert_eq!(tokens[2], Token::LeftBrace);
        assert_eq!(tokens[3], Token::RightBrace);
        assert_eq!(tokens[4], Token::Semicolon);
        assert_eq!(tokens[5], Token::Colon);
        assert_eq!(tokens[6], Token::Equals);
        assert_eq!(tokens[7], Token::U8);
        assert_eq!(tokens[8], Token::U16);
    }

    #[test]
    fn test_hex_number() {
        let input = "0x17 0x0303";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0], Token::Number(0x17));
        assert_eq!(tokens[1], Token::Number(0x0303));
    }

    #[test]
    fn test_identifier() {
        let input = "Tls13Record content_type";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0], Token::Identifier("Tls13Record".to_string()));
        assert_eq!(tokens[1], Token::Identifier("content_type".to_string()));
    }
}
