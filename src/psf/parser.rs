//! PSF Parser - Builds AST from tokens

use super::lexer::{Lexer, Token};
use super::types::*;
use std::collections::HashMap;

pub struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    pub fn new(input: &str) -> Result<Self, String> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize()?;

        Ok(Self {
            tokens,
            position: 0,
        })
    }

    pub fn parse(&mut self) -> Result<PsfSpec, String> {
        let mut formats = HashMap::new();
        let mut semantics = Vec::new();
        let mut sequence = Vec::new();
        let crypto = None;

        while !self.is_eof() {
            self.skip_newlines();

            if self.is_eof() {
                break;
            }

            // Parse sections
            if self.match_token(&Token::At) {
                self.advance();

                let ident = self.expect_identifier()?;

                match ident.as_str() {
                    "SEGMENT" => {
                        self.skip_newlines();
                        self.expect_token(&Token::Dot)?;
                        let section = self.expect_identifier()?;

                        match section.as_str() {
                            "FORMATS" => {
                                match self.parse_formats() {
                                    Ok(parsed_formats) => formats.extend(parsed_formats),
                                    Err(_) => {
                                        // Skip to next section on error
                                        self.skip_until_section();
                                    }
                                }
                            }
                            "SEMANTICS" => {
                                match self.parse_semantics() {
                                    Ok(parsed_semantics) => semantics.extend(parsed_semantics),
                                    Err(e) => {
                                        // DEBUG: Print the error instead of silently skipping
                                        eprintln!("ERROR parsing SEMANTICS section: {}", e);
                                        return Err(format!("Semantic parsing failed: {}", e));
                                    }
                                }
                            }
                            "SEQUENCE" => {
                                match self.parse_sequence() {
                                    Ok(parsed_sequence) => sequence.extend(parsed_sequence),
                                    Err(_) => {
                                        // Skip to next section on error
                                        self.skip_until_section();
                                    }
                                }
                            }
                            _ => {
                                // Skip unknown sections
                                self.skip_until_section();
                            }
                        }
                    }
                    _ => {
                        self.skip_until_section();
                    }
                }
            } else {
                self.advance();
            }
        }

        Ok(PsfSpec {
            name: "protocol".to_string(),
            formats,
            semantics,
            sequence,
            crypto,
        })
    }

    fn parse_formats(&mut self) -> Result<HashMap<String, MessageFormat>, String> {
        let mut formats = HashMap::new();

        while !self.is_eof() && !self.match_token(&Token::At) {
            self.skip_newlines();

            if self.is_eof() || self.match_token(&Token::At) {
                break;
            }

            if self.match_token(&Token::Define) {
                self.advance();
                let name = self.expect_identifier()?;

                let mut fields = Vec::new();

                // Skip newlines after DEFINE name
                self.skip_newlines();

                // Parse fields - each field is { NAME: ... ; TYPE: ... }
                // Fields are NOT wrapped in an outer brace
                while !self.is_eof() && !self.match_token(&Token::At) {
                    self.skip_newlines();

                    // Check for end of DEFINE (semicolon or next section)
                    if self.match_token(&Token::Semicolon) {
                        self.advance();
                        break;
                    }

                    if self.match_token(&Token::At) {
                        break;
                    }

                    // Each field starts with {
                    if !self.match_token(&Token::LeftBrace) {
                        // If not a field, skip to next section
                        if self.match_token(&Token::Define) {
                            break;
                        }
                        self.advance();
                        continue;
                    }

                    self.advance(); // consume {

                    // Parse field: { NAME: field_name ; TYPE: field_type }
                    let mut field_name = String::new();
                    let mut field_type = None;

                    while !self.match_token(&Token::RightBrace) && !self.is_eof() {
                        let key = self.expect_identifier()?;
                        self.expect_token(&Token::Colon)?;

                        if key == "NAME" {
                            field_name = self.expect_identifier()?;
                        } else if key == "TYPE" {
                            field_type = Some(self.parse_field_type()?);
                        }

                        if self.match_token(&Token::Semicolon) {
                            self.advance();
                        }
                    }

                    if self.match_token(&Token::RightBrace) {
                        self.advance(); // consume }
                    }

                    if self.match_token(&Token::Comma) {
                        self.advance();
                    }

                    // Add field if we got both name and type
                    if !field_name.is_empty() && field_type.is_some() {
                        fields.push(FieldDefinition {
                            name: field_name,
                            field_type: field_type.unwrap(),
                        });
                    }
                }

                formats.insert(name.clone(), MessageFormat { name, fields });
            } else {
                self.advance();
            }
        }

        Ok(formats)
    }

    fn parse_field_type(&mut self) -> Result<FieldType, String> {
        let token = self.current();

        match token {
            Token::U1 => {
                self.advance();
                Ok(FieldType::UInt(1))  // Treat as 1 byte for now
            }
            Token::U2 => {
                self.advance();
                Ok(FieldType::UInt(1))  // Treat as 1 byte for now
            }
            Token::U4 => {
                self.advance();
                Ok(FieldType::UInt(1))  // Treat as 1 byte for now
            }
            Token::U5 => {
                self.advance();
                Ok(FieldType::UInt(1))  // Treat as 1 byte for now
            }
            Token::U7 => {
                self.advance();
                Ok(FieldType::UInt(1))  // Treat as 1 byte for now
            }
            Token::U8 => {
                self.advance();
                Ok(FieldType::UInt(1))
            }
            Token::U16 => {
                self.advance();
                Ok(FieldType::UInt(2))
            }
            Token::U24 => {
                self.advance();
                Ok(FieldType::UInt(3))
            }
            Token::U32 => {
                self.advance();
                Ok(FieldType::UInt(4))
            }
            Token::U64 => {
                self.advance();
                Ok(FieldType::UInt(8))
            }
            Token::Varint => {
                self.advance();
                Ok(FieldType::UInt(4))  // Treat as u32 for now
            }
            Token::LeftBracket => {
                // Array type: [u8; N] or [u8; variable] or [u8; length * 4]
                self.advance(); // consume [
                let element_type = self.parse_field_type()?;
                self.expect_token(&Token::Semicolon)?;

                if let Token::Number(size) = self.current() {
                    let size = *size as usize;
                    self.advance();

                    // Check for arithmetic operators (*, +, -) and skip them
                    while self.match_token(&Token::Star) || self.match_token(&Token::Plus) || self.match_token(&Token::Minus) {
                        self.advance();
                        // Skip the operand
                        if let Token::Number(_) = self.current() {
                            self.advance();
                        } else if let Token::Identifier(_) = self.current() {
                            self.advance();
                        }
                    }

                    self.expect_token(&Token::RightBracket)?;
                    Ok(FieldType::ByteArray(size))
                } else if let Token::Identifier(name) = self.current() {
                    let mut name = name.clone();
                    self.advance();

                    // Check for dotted field name (e.g., header.length)
                    if self.match_token(&Token::Dot) {
                        self.advance();
                        let field = self.expect_identifier()?;
                        name = format!("{}.{}", name, field);
                    }

                    // Check for arithmetic operators (*, +, -) and skip them
                    while self.match_token(&Token::Star) || self.match_token(&Token::Plus) || self.match_token(&Token::Minus) {
                        self.advance();
                        // Skip the operand
                        if let Token::Number(_) = self.current() {
                            self.advance();
                        } else if let Token::Identifier(_) = self.current() {
                            self.advance();
                            // Handle dotted names in operands too
                            if self.match_token(&Token::Dot) {
                                self.advance();
                                let _ = self.expect_identifier()?;
                            }
                        }
                    }

                    self.expect_token(&Token::RightBracket)?;
                    if name == "variable" {
                        Ok(FieldType::String)
                    } else {
                        Ok(FieldType::ByteArrayDynamic(name))
                    }
                } else {
                    Err("Expected array size or field name".to_string())
                }
            }
            Token::Identifier(name) => {
                let name = name.clone();
                self.advance();
                Ok(FieldType::Nested(name))
            }
            _ => Err(format!("Unexpected type token: {:?}", token)),
        }
    }

    fn parse_semantics(&mut self) -> Result<Vec<SemanticRule>, String> {
        let mut semantics = Vec::new();

        while !self.is_eof() && !self.match_token(&Token::At) {
            self.skip_newlines();

            if self.is_eof() || self.match_token(&Token::At) {
                break;
            }

            // Support two syntax styles:
            // 1. Brace syntax: { FORMAT: Foo; FIELD: bar; SEMANTIC: LENGTH };
            // 2. DEFINE syntax: DEFINE Foo.bar SEMANTIC: LENGTH;

            if self.match_token(&Token::Define) {
                self.advance();

                // Parse Format.Field - if we can't get an identifier, skip this entry
                let format_field = match self.expect_identifier() {
                    Ok(id) => id,
                    Err(_) => {
                        self.skip_until_newline();
                        continue;
                    }
                };

                // Split on dot if present
                let (format, field) = if let Some(dot_pos) = format_field.find('.') {
                    (format_field[..dot_pos].to_string(), format_field[dot_pos+1..].to_string())
                } else {
                    // If no dot, skip this entry
                    self.skip_until_newline();
                    continue;
                };

                self.skip_newlines();

                // Parse semantic properties (SEMANTIC:, FIXED_VALUE:, VALUES:, etc.)
                let mut semantic = None;

                while !self.is_eof() && !self.match_token(&Token::At) && !self.match_token(&Token::Define) {
                    if self.match_token(&Token::Newline) {
                        // Check if next line is indented or a new section
                        self.skip_newlines();
                        if self.match_token(&Token::At) || self.match_token(&Token::Define) || self.match_token(&Token::Role) {
                            break;
                        }
                        // If we see another newline or EOF, we're done with this DEFINE block
                        if self.match_token(&Token::Newline) || self.is_eof() {
                            break;
                        }
                        continue;
                    }

                    // Try to read a key - if it's not an identifier, break
                    if !matches!(self.current(), Token::Identifier(_) |
                                 Token::Semantic | Token::FixedValue | Token::Field | Token::Format) {
                        break;
                    }

                    let key = match self.current() {
                        Token::Identifier(s) => s.clone(),
                        Token::Semantic => "SEMANTIC".to_string(),
                        Token::FixedValue => "FIXED_VALUE".to_string(),
                        _ => {
                            self.advance();
                            continue;
                        }
                    };
                    self.advance();

                    if !self.match_token(&Token::Colon) {
                        // No colon, not a valid property, skip this line
                        self.skip_until_semicolon_or_newline();
                        continue;
                    }
                    self.advance();

                    match key.as_str() {
                        "SEMANTIC" => {
                            semantic = Some(self.parse_semantic_type()?);
                        }
                        "FIXED_VALUE" => {
                            // Parse fixed value (number, char, or string)
                            let value = if let Token::Number(n) = self.current() {
                                *n
                            } else if let Token::Char(c) = self.current() {
                                *c as u64
                            } else if let Token::String(_s) = self.current() {
                                // For strings (including large hex strings), just use 0 as placeholder
                                0
                            } else {
                                return Err(format!("Expected value after FIXED_VALUE, got {:?}", self.current()));
                            };
                            self.advance();
                            semantic = Some(SemanticType::FixedValue(value));
                        }
                        "VALUES" => {
                            // Skip VALUES for now (enum definitions)
                            self.skip_until_semicolon_or_newline();
                        }
                        _ => {
                            self.skip_until_semicolon_or_newline();
                        }
                    }

                    if self.match_token(&Token::Semicolon) {
                        self.advance();
                        break;
                    }
                }

                if !format.is_empty() && !field.is_empty() && semantic.is_some() {
                    semantics.push(SemanticRule {
                        format,
                        field,
                        semantic: semantic.unwrap(),
                    });
                }

            } else if self.match_token(&Token::LeftBrace) {
                self.advance();

                let mut format = String::new();
                let mut field = String::new();
                let mut semantic = None;

                while !self.match_token(&Token::RightBrace) && !self.is_eof() {
                    let key = self.expect_identifier()?;
                    self.expect_token(&Token::Colon)?;

                    match key.as_str() {
                        "FORMAT" => {
                            format = self.expect_identifier()?;
                        }
                        "FIELD" => {
                            field = self.expect_identifier()?;
                        }
                        "SEMANTIC" => {
                            semantic = Some(self.parse_semantic_type()?);
                        }
                        _ => {
                            // Skip unknown keys
                            self.skip_until(&Token::Semicolon);
                        }
                    }

                    if self.match_token(&Token::Semicolon) {
                        self.advance();
                    }
                }

                if self.match_token(&Token::RightBrace) {
                    self.advance();
                }

                if self.match_token(&Token::Semicolon) {
                    self.advance();
                }

                if !format.is_empty() && !field.is_empty() && semantic.is_some() {
                    semantics.push(SemanticRule {
                        format,
                        field,
                        semantic: semantic.unwrap(),
                    });
                }
            } else {
                self.advance();
            }
        }

        Ok(semantics)
    }

    fn parse_semantic_type(&mut self) -> Result<SemanticType, String> {
        let token = self.current();

        match token {
            Token::FixedValue => {
                self.advance();
                self.expect_token(&Token::LeftParen)?;

                // Skip newlines after opening paren (for multiline arrays)
                self.skip_newlines();

                // Parse first value (number or char) - keep as u64 to avoid truncation
                let first_value = match self.current() {
                    Token::Number(n) => *n,
                    Token::Char(c) => *c as u64,
                    _ => return Err(format!("Expected number or char in FIXED_VALUE, got {:?}", self.current())),
                };
                self.advance();

                // Check if there's a comma (indicating byte array)
                if self.match_token(&Token::Comma) {
                    // Parse byte array: FIXED_VALUE(val1, val2, val3, ...)
                    let mut bytes = vec![first_value as u8];

                    while self.match_token(&Token::Comma) {
                        self.advance(); // consume comma

                        // Skip newlines for multiline arrays
                        self.skip_newlines();

                        // Parse next value
                        let value = match self.current() {
                            Token::Number(n) => *n as u8,
                            Token::Char(c) => *c as u8,
                            _ => return Err(format!("Expected number or char in FIXED_VALUE array, got {:?}", self.current())),
                        };
                        self.advance();
                        bytes.push(value);
                    }

                    // Skip newlines before closing paren
                    self.skip_newlines();
                    self.expect_token(&Token::RightParen)?;
                    Ok(SemanticType::FixedBytes(bytes))
                } else {
                    // Single value: FIXED_VALUE(val)
                    self.expect_token(&Token::RightParen)?;
                    Ok(SemanticType::FixedValue(first_value))
                }
            }
            Token::Length => {
                self.advance();
                Ok(SemanticType::Length)
            }
            Token::Payload => {
                self.advance();
                Ok(SemanticType::Payload)
            }
            Token::Mac => {
                self.advance();
                Ok(SemanticType::Mac)
            }
            Token::Padding => {
                self.advance();
                Ok(SemanticType::Padding)
            }
            Token::Identifier(ref s) if s == "RANDOM" => {
                self.advance();
                Ok(SemanticType::Random)
            }
            Token::Identifier(ref s) if s == "FIXED_BYTES" => {
                self.advance();
                self.expect_token(&Token::LeftParen)?;

                // Expect left bracket for array
                self.skip_newlines();
                self.expect_token(&Token::LeftBracket)?;

                // Parse byte array
                let mut bytes = Vec::new();
                self.skip_newlines();

                while !self.match_token(&Token::RightBracket) && !self.is_eof() {
                    // Parse value
                    let value = match self.current() {
                        Token::Number(n) => *n as u8,
                        Token::Char(c) => *c as u8,
                        _ => return Err(format!("Expected number or char in FIXED_BYTES array, got {:?}", self.current())),
                    };
                    self.advance();
                    bytes.push(value);

                    // Skip optional comma and newlines
                    if self.match_token(&Token::Comma) {
                        self.advance();
                    }
                    self.skip_newlines();
                }

                // Expect right bracket
                self.expect_token(&Token::RightBracket)?;

                // Skip newlines before closing paren
                self.skip_newlines();

                // Expect right paren
                self.expect_token(&Token::RightParen)?;

                Ok(SemanticType::FixedBytes(bytes))
            }
            Token::CommandType | Token::Identifier(_) => {
                // Generic semantic type identifier (COMMAND_TYPE, STATUS_CODE, etc.)
                // Just skip it for now - we'll use a placeholder
                self.advance();
                Ok(SemanticType::Length)  // Use Length as placeholder for now
            }
            _ => Err(format!("Unknown semantic type: {:?}", token)),
        }
    }

    fn parse_sequence(&mut self) -> Result<Vec<SequenceRule>, String> {
        let mut sequence = Vec::new();

        while !self.is_eof() && !self.match_token(&Token::At) {
            self.skip_newlines();

            if self.is_eof() || self.match_token(&Token::At) {
                break;
            }

            // Support two syntax styles:
            // 1. Brace syntax: { ROLE: CLIENT; PHASE: DATA; FORMAT: Foo };
            // 2. Indented syntax:
            //    ROLE: CLIENT
            //      PHASE: DATA
            //        FORMAT: Foo;

            if self.match_token(&Token::Role) {
                self.advance();
                self.expect_token(&Token::Colon)?;

                let role_str = self.expect_identifier()?;
                let role = match role_str.as_str() {
                    "CLIENT" => Role::Client,
                    "SERVER" => Role::Server,
                    _ => return Err(format!("Unknown role: {}", role_str)),
                };

                self.skip_newlines();

                // Parse nested PHASE blocks
                while !self.is_eof() && !self.match_token(&Token::At) && !self.match_token(&Token::Role) {
                    if !self.match_token(&Token::Phase) {
                        if self.match_token(&Token::Newline) {
                            self.skip_newlines();
                            continue;
                        }
                        break;
                    }

                    self.advance(); // consume PHASE
                    self.expect_token(&Token::Colon)?;

                    let phase = self.expect_identifier()?;
                    self.skip_newlines();

                    // Parse nested FORMAT entries
                    while !self.is_eof() && !self.match_token(&Token::At) && !self.match_token(&Token::Role) && !self.match_token(&Token::Phase) {
                        if !self.match_token(&Token::Format) {
                            if self.match_token(&Token::Newline) {
                                self.skip_newlines();
                                continue;
                            }
                            break;
                        }

                        self.advance(); // consume FORMAT
                        self.expect_token(&Token::Colon)?;

                        let format = self.expect_identifier()?;

                        sequence.push(SequenceRule {
                            role: role.clone(),
                            phase: phase.clone(),
                            format,
                        });

                        if self.match_token(&Token::Semicolon) {
                            self.advance();
                        }

                        self.skip_newlines();
                    }
                }

            } else if self.match_token(&Token::LeftBrace) {
                self.advance();

                let mut role = None;
                let mut phase = String::new();
                let mut format = String::new();

                while !self.match_token(&Token::RightBrace) && !self.is_eof() {
                    let key = self.expect_identifier()?;
                    self.expect_token(&Token::Colon)?;

                    match key.as_str() {
                        "ROLE" => {
                            let role_str = self.expect_identifier()?;
                            role = Some(match role_str.as_str() {
                                "CLIENT" => Role::Client,
                                "SERVER" => Role::Server,
                                _ => return Err(format!("Unknown role: {}", role_str)),
                            });
                        }
                        "PHASE" => {
                            phase = self.expect_identifier()?;
                        }
                        "FORMAT" => {
                            format = self.expect_identifier()?;
                        }
                        _ => {
                            self.skip_until(&Token::Semicolon);
                        }
                    }

                    if self.match_token(&Token::Semicolon) {
                        self.advance();
                    }
                }

                if self.match_token(&Token::RightBrace) {
                    self.advance();
                }

                if self.match_token(&Token::Semicolon) {
                    self.advance();
                }

                if let Some(role) = role {
                    if !phase.is_empty() && !format.is_empty() {
                        sequence.push(SequenceRule {
                            role,
                            phase,
                            format,
                        });
                    }
                }
            } else {
                self.advance();
            }
        }

        Ok(sequence)
    }

    // Utility methods

    fn current(&self) -> &Token {
        &self.tokens[self.position]
    }

    fn advance(&mut self) {
        if self.position < self.tokens.len() {
            self.position += 1;
        }
    }

    fn is_eof(&self) -> bool {
        matches!(self.current(), Token::Eof)
    }

    fn match_token(&self, token: &Token) -> bool {
        std::mem::discriminant(self.current()) == std::mem::discriminant(token)
    }

    fn expect_token(&mut self, token: &Token) -> Result<(), String> {
        if !self.match_token(token) {
            return Err(format!("Expected {:?}, got {:?}", token, self.current()));
        }
        self.advance();
        Ok(())
    }

    fn expect_identifier(&mut self) -> Result<String, String> {
        // Accept both identifiers and keywords as identifiers
        let name = match self.current() {
            Token::Identifier(n) => n.clone(),
            Token::Segment => "SEGMENT".to_string(),
            Token::Define => "DEFINE".to_string(),
            Token::Role => "ROLE".to_string(),
            Token::Phase => "PHASE".to_string(),
            Token::Format => "FORMAT".to_string(),
            Token::Field => "FIELD".to_string(),
            Token::Semantic => "SEMANTIC".to_string(),
            Token::FixedValue => "FIXED_VALUE".to_string(),
            Token::Length => "LENGTH".to_string(),
            Token::Payload => "PAYLOAD".to_string(),
            Token::Padding => "PADDING".to_string(),
            Token::CommandType => "COMMAND_TYPE".to_string(),
            Token::U1 => "u1".to_string(),
            Token::U2 => "u2".to_string(),
            Token::U4 => "u4".to_string(),
            Token::U5 => "u5".to_string(),
            Token::U7 => "u7".to_string(),
            Token::U8 => "u8".to_string(),
            Token::U16 => "u16".to_string(),
            Token::U24 => "u24".to_string(),
            Token::U32 => "u32".to_string(),
            Token::U64 => "u64".to_string(),
            Token::Varint => "varint".to_string(),
            _ => return Err(format!("Expected identifier, got {:?}", self.current())),
        };
        self.advance();
        Ok(name)
    }

    fn expect_number(&mut self) -> Result<u64, String> {
        if let Token::Number(n) = self.current() {
            let n = *n;
            self.advance();
            Ok(n)
        } else {
            Err(format!("Expected number, got {:?}", self.current()))
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.current(), Token::Newline) {
            self.advance();
        }
    }

    fn skip_until(&mut self, token: &Token) {
        while !self.is_eof() && !self.match_token(token) {
            self.advance();
        }
    }

    fn skip_until_section(&mut self) {
        while !self.is_eof() && !self.match_token(&Token::At) {
            self.advance();
        }
    }

    fn skip_until_newline(&mut self) {
        while !self.is_eof() && !self.match_token(&Token::Newline) {
            self.advance();
        }
    }

    fn skip_until_semicolon_or_newline(&mut self) {
        while !self.is_eof() && !self.match_token(&Token::Semicolon) && !self.match_token(&Token::Newline) {
            self.advance();
        }
    }
}
