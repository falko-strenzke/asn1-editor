// Copyright 2026 Falko Strenzke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ASN.1 specification (schema) support.
//!
//! A generic parser for 1988-syntax ASN.1 modules (the subset used by the
//! RFC 5280 modules in `specs/asn1/`), and a structural matcher that
//! checks a parsed BER/DER tree against every type definition and labels
//! the tree nodes with the field and type names of the best match.
//!
//! Value assignments, constraints (`SIZE`, ranges), named INTEGER values
//! and named BIT STRING bits are parsed and discarded: they do not affect
//! the structural match.

use std::collections::HashMap;
use std::path::Path;

use crate::ber::{Class, Node, TAG_SEQUENCE, TAG_SET};

const MAX_RESOLVE_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TagMode {
    /// No IMPLICIT/EXPLICIT keyword: the module default applies.
    Default,
    Implicit,
    Explicit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    /// Reference to a named type (resolved via the whole database).
    Reference(String),
    /// ANY / ANY DEFINED BY ...: matches any single element.
    Any,
    /// A universal primitive type, identified by its tag number.
    Primitive(u32),
    Sequence(Vec<Field>),
    Set(Vec<Field>),
    SequenceOf(Box<Type>),
    SetOf(Box<Type>),
    Choice(Vec<Field>),
    Tagged { class: Class, number: u32, mode: TagMode, inner: Box<Type> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    /// OPTIONAL or DEFAULT: the component may be absent.
    pub optional: bool,
}

#[derive(Clone, Debug)]
pub struct TypeDef {
    pub name: String,
    pub ty: Type,
    /// Module tagging default (DEFINITIONS IMPLICIT TAGS).
    pub implicit_tags: bool,
    pub module: String,
    /// File the definition came from (for display).
    pub source: String,
}

#[derive(Default)]
pub struct SpecDb {
    pub types: Vec<TypeDef>,
    index: HashMap<String, usize>,
}

impl SpecDb {
    pub fn add(&mut self, defs: Vec<TypeDef>) {
        for def in defs {
            // First definition of a name wins.
            self.index.entry(def.name.clone()).or_insert(self.types.len());
            self.types.push(def);
        }
    }

    pub fn resolve(&self, name: &str) -> Option<&TypeDef> {
        self.index.get(name).map(|&i| &self.types[i])
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Number(u64),
    Assign, // ::=
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Semicolon,
    Ellipsis,
    Other(char),
}

fn tokenize(src: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '-' && chars.get(i + 1) == Some(&'-') {
            // Comment: to the next "--" or end of line.
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                if chars[i] == '-' && chars.get(i + 1) == Some(&'-') {
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else if c == ':' && chars.get(i + 1) == Some(&':') && chars.get(i + 2) == Some(&'=') {
            toks.push(Tok::Assign);
            i += 3;
        } else if c == '.' && chars.get(i + 1) == Some(&'.') {
            if chars.get(i + 2) == Some(&'.') {
                toks.push(Tok::Ellipsis);
                i += 3;
            } else {
                toks.push(Tok::Other('…')); // ".." range, only inside constraints
                i += 2;
            }
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '-' || chars[i] == '_')
            {
                // A '-' only continues the identifier when not "--" (comment).
                if chars[i] == '-' && chars.get(i + 1) == Some(&'-') {
                    break;
                }
                i += 1;
            }
            toks.push(Tok::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let n: u64 = chars[start..i].iter().collect::<String>().parse().unwrap_or(0);
            toks.push(Tok::Number(n));
        } else {
            toks.push(match c {
                '{' => Tok::LBrace,
                '}' => Tok::RBrace,
                '[' => Tok::LBracket,
                ']' => Tok::RBracket,
                '(' => Tok::LParen,
                ')' => Tok::RParen,
                ',' => Tok::Comma,
                ';' => Tok::Semicolon,
                other => Tok::Other(other),
            });
            i += 1;
        }
    }
    toks
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    source: String,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, String> {
        let ctx: Vec<String> = self.toks[self.pos.saturating_sub(3)..(self.pos + 4).min(self.toks.len())]
            .iter()
            .map(|t| format!("{:?}", t))
            .collect();
        Err(format!(
            "{}: {} (near token {} of {}: {})",
            self.source,
            msg.into(),
            self.pos,
            self.toks.len(),
            ctx.join(" ")
        ))
    }

    /// Skip a balanced group that starts with the token just consumed.
    fn skip_balanced(&mut self, open: Tok, close: Tok) {
        let mut depth = 1;
        while depth > 0 {
            match self.next() {
                Some(t) if t == open => depth += 1,
                Some(t) if t == close => depth -= 1,
                Some(_) => {}
                None => break,
            }
        }
    }

    /// Skip any number of trailing constraints: "(...)".
    fn skip_constraints(&mut self) {
        while self.eat(&Tok::LParen) {
            self.skip_balanced(Tok::LParen, Tok::RParen);
        }
    }

    /// Parse all modules in the token stream; returns their type defs.
    fn parse_file(&mut self) -> Result<Vec<TypeDef>, String> {
        let mut defs = Vec::new();
        while self.peek().is_some() {
            defs.extend(self.parse_module()?);
        }
        Ok(defs)
    }

    fn parse_module(&mut self) -> Result<Vec<TypeDef>, String> {
        let module = match self.next() {
            Some(Tok::Ident(name)) => name,
            _ => return self.err("expected module name"),
        };
        if self.eat(&Tok::LBrace) {
            self.skip_balanced(Tok::LBrace, Tok::RBrace); // module OID
        }
        if !self.eat_kw("DEFINITIONS") {
            return self.err("expected DEFINITIONS");
        }
        let mut implicit_tags = false;
        while let Some(Tok::Ident(word)) = self.peek() {
            match word.as_str() {
                "IMPLICIT" => implicit_tags = true,
                "EXPLICIT" | "AUTOMATIC" | "TAGS" | "EXTENSIBILITY" | "IMPLIED" => {}
                _ => break,
            }
            self.pos += 1;
        }
        if !self.eat(&Tok::Assign) {
            return self.err("expected ::= after DEFINITIONS");
        }
        if !self.eat_kw("BEGIN") {
            return self.err("expected BEGIN");
        }

        let mut defs = Vec::new();
        loop {
            if self.eat_kw("END") {
                break;
            }
            if self.eat_kw("IMPORTS") || self.eat_kw("EXPORTS") {
                while let Some(t) = self.next() {
                    if t == Tok::Semicolon {
                        break;
                    }
                }
                continue;
            }
            let name = match self.next() {
                Some(Tok::Ident(name)) => name,
                Some(_) => return self.err("expected assignment"),
                None => return self.err("unexpected end of module (missing END)"),
            };
            let type_assignment = name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && self.peek() == Some(&Tok::Assign);
            if type_assignment {
                self.pos += 1; // ::=
                let ty = self.parse_type()?;
                defs.push(TypeDef {
                    name,
                    ty,
                    implicit_tags,
                    module: module.clone(),
                    source: self.source.clone(),
                });
            } else {
                // Value assignment: "name Type ::= value" — parse and drop.
                let _ = self.parse_type()?;
                if !self.eat(&Tok::Assign) {
                    return self.err(format!("expected ::= in value assignment '{}'", name));
                }
                self.skip_value();
            }
        }
        Ok(defs)
    }

    /// Skip one value (of a value assignment or DEFAULT).
    fn skip_value(&mut self) {
        if self.eat(&Tok::LBrace) {
            self.skip_balanced(Tok::LBrace, Tok::RBrace);
        } else {
            self.next();
        }
    }

    fn parse_type(&mut self) -> Result<Type, String> {
        // Optional tag: [ CLASS? number ]
        if self.eat(&Tok::LBracket) {
            let class = if self.eat_kw("APPLICATION") {
                Class::Application
            } else if self.eat_kw("PRIVATE") {
                Class::Private
            } else if self.eat_kw("UNIVERSAL") {
                Class::Universal
            } else {
                Class::ContextSpecific
            };
            let number = match self.next() {
                Some(Tok::Number(n)) => n as u32,
                _ => return self.err("expected tag number"),
            };
            if !self.eat(&Tok::RBracket) {
                return self.err("expected ]");
            }
            let mode = if self.eat_kw("IMPLICIT") {
                TagMode::Implicit
            } else if self.eat_kw("EXPLICIT") {
                TagMode::Explicit
            } else {
                TagMode::Default
            };
            let inner = self.parse_type()?;
            return Ok(Type::Tagged { class, number, mode, inner: Box::new(inner) });
        }

        let name = match self.next() {
            Some(Tok::Ident(name)) => name,
            _ => return self.err("expected type"),
        };
        let ty = match name.as_str() {
            "SEQUENCE" | "SET" => {
                let seq = name == "SEQUENCE";
                if self.eat(&Tok::LBrace) {
                    let fields = self.parse_fields()?;
                    if seq { Type::Sequence(fields) } else { Type::Set(fields) }
                } else {
                    // SEQUENCE [SIZE (...)] OF Type
                    self.eat_kw("SIZE");
                    self.skip_constraints();
                    if !self.eat_kw("OF") {
                        return self.err("expected OF after SEQUENCE/SET");
                    }
                    // "SEQUENCE OF fieldName Type" is legal; skip the name.
                    if let (Some(Tok::Ident(first)), Some(Tok::Ident(_))) =
                        (self.peek(), self.toks.get(self.pos + 1))
                    {
                        if first.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                            self.pos += 1;
                        }
                    }
                    let elem = Box::new(self.parse_type()?);
                    if seq { Type::SequenceOf(elem) } else { Type::SetOf(elem) }
                }
            }
            "CHOICE" => {
                if !self.eat(&Tok::LBrace) {
                    return self.err("expected { after CHOICE");
                }
                Type::Choice(self.parse_fields()?)
            }
            "INTEGER" | "ENUMERATED" => {
                if self.eat(&Tok::LBrace) {
                    self.skip_balanced(Tok::LBrace, Tok::RBrace); // named values
                }
                Type::Primitive(if name == "INTEGER" { 2 } else { 10 })
            }
            "BIT" | "OCTET" => {
                if !self.eat_kw("STRING") {
                    return self.err("expected STRING");
                }
                if self.eat(&Tok::LBrace) {
                    self.skip_balanced(Tok::LBrace, Tok::RBrace); // named bits
                }
                Type::Primitive(if name == "BIT" { 3 } else { 4 })
            }
            "OBJECT" => {
                if !self.eat_kw("IDENTIFIER") {
                    return self.err("expected IDENTIFIER");
                }
                Type::Primitive(6)
            }
            "ANY" => {
                if self.eat_kw("DEFINED") {
                    if !self.eat_kw("BY") {
                        return self.err("expected BY");
                    }
                    self.next(); // the field name
                }
                Type::Any
            }
            "BOOLEAN" => Type::Primitive(1),
            "NULL" => Type::Primitive(5),
            "REAL" => Type::Primitive(9),
            "ObjectDescriptor" => Type::Primitive(7),
            "EXTERNAL" => Type::Primitive(8),
            "EMBEDDED" => {
                self.eat_kw("PDV");
                Type::Primitive(11)
            }
            "UTF8String" => Type::Primitive(12),
            "RELATIVE-OID" => Type::Primitive(13),
            "NumericString" => Type::Primitive(18),
            "PrintableString" => Type::Primitive(19),
            "TeletexString" | "T61String" => Type::Primitive(20),
            "VideotexString" => Type::Primitive(21),
            "IA5String" => Type::Primitive(22),
            "UTCTime" => Type::Primitive(23),
            "GeneralizedTime" => Type::Primitive(24),
            "GraphicString" => Type::Primitive(25),
            "VisibleString" | "ISO646String" => Type::Primitive(26),
            "GeneralString" => Type::Primitive(27),
            "UniversalString" => Type::Primitive(28),
            "BMPString" => Type::Primitive(30),
            _ if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) => {
                Type::Reference(name)
            }
            _ => return self.err(format!("unexpected type '{}'", name)),
        };
        self.skip_constraints();
        Ok(ty)
    }

    /// Components of SEQUENCE/SET/CHOICE (between braces, '{' consumed).
    fn parse_fields(&mut self) -> Result<Vec<Field>, String> {
        let mut fields = Vec::new();
        loop {
            if self.eat(&Tok::RBrace) {
                break;
            }
            if self.eat(&Tok::Ellipsis) {
                // Extension marker; the comma or brace follows.
                self.eat(&Tok::Comma);
                continue;
            }
            let name = match self.next() {
                Some(Tok::Ident(name)) => name,
                _ => return self.err("expected component name"),
            };
            let ty = self.parse_type()?;
            let mut optional = false;
            if self.eat_kw("OPTIONAL") {
                optional = true;
            } else if self.eat_kw("DEFAULT") {
                optional = true;
                self.skip_value();
            }
            fields.push(Field { name, ty, optional });
            if !self.eat(&Tok::Comma) {
                if self.eat(&Tok::RBrace) {
                    break;
                }
                return self.err("expected , or } in component list");
            }
        }
        Ok(fields)
    }
}

/// Parse one specification file (which may contain several modules).
pub fn parse_spec(source_name: &str, text: &str) -> Result<Vec<TypeDef>, String> {
    let mut parser =
        Parser { toks: tokenize(text), pos: 0, source: source_name.to_string() };
    parser.parse_file()
}

/// Load every file in a specs directory into one database. Returns the
/// database and a list of per-file errors (unparsable files are skipped).
pub fn load_dir(dir: &Path) -> (SpecDb, Vec<String>) {
    let mut db = SpecDb::default();
    let mut errors = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (db, errors);
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths.iter().filter(|p| p.is_file()) {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        match std::fs::read_to_string(path) {
            Ok(text) => match parse_spec(&name, &text) {
                Ok(defs) => db.add(defs),
                Err(e) => errors.push(e),
            },
            Err(e) => errors.push(format!("{}: {}", name, e)),
        }
    }
    (db, errors)
}

/// Find the specs directory: $ASN1_EDITOR_SPECS, ./specs/asn1, or
/// specs/asn1 next to the executable's ancestor directories.
pub fn default_spec_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("ASN1_EDITOR_SPECS") {
        return Some(std::path::PathBuf::from(dir));
    }
    let cwd_specs = Path::new("specs/asn1");
    if cwd_specs.is_dir() {
        return Some(cwd_specs.to_path_buf());
    }
    let exe = std::env::current_exe().ok()?;
    for anc in exe.ancestors().skip(1) {
        let cand = anc.join("specs/asn1");
        if cand.is_dir() {
            return Some(cand);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

/// Annotation for one tree node, produced by a successful match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    /// Component name within the enclosing SEQUENCE/SET/CHOICE.
    pub field: Option<String>,
    /// Spec type name(s), e.g. "TBSCertificate" or "Time.utcTime".
    pub type_name: String,
}

#[derive(Clone, Debug)]
pub struct Identification {
    pub type_name: String,
    pub source: String,
    pub labels: HashMap<Vec<usize>, Label>,
}

#[derive(Clone, Default)]
struct Ctx {
    field: Option<String>,
    names: Vec<String>,
}

/// Try to identify the document (a single top-level element) against every
/// type in the database; the match that labels the most nodes wins.
///
/// Ties in node count are broken in favor of the lexicographically greater
/// `source` (spec filename). Bundled modules are named by RFC number, so
/// this makes a newer RFC supersede an older one it obsoletes when a
/// document matches both — e.g. an RFC 5208 PKCS#8 `PrivateKeyInfo` and
/// the RFC 5958 `OneAsymmetricKey` that replaces it match the same v1 key
/// identically, and `rfc5958` (> `rfc5208`) is preferred. Within one
/// source, ties keep the first-defined type (stable file order).
///
/// After the top-level match, ASN.1 nested inside encapsulating OCTET /
/// BIT STRING values (which the top match treats as opaque and never
/// descends into) is labeled too, by independently identifying each
/// encapsulated sub-structure — e.g. the RFC 5915 `ECPrivateKey` carried
/// in a PKCS#8 `privateKey` OCTET STRING gets its fields named. The
/// document's overall `type_name`/`source` still come from the top match;
/// only extra per-node labels are added.
pub fn identify(db: &SpecDb, roots: &[Node]) -> Option<Identification> {
    if roots.len() != 1 {
        return None;
    }
    let mut best: Option<(usize, Identification)> = None;
    for def in &db.types {
        let mut out = Vec::new();
        let ctx = Ctx { field: None, names: vec![def.name.clone()] };
        if match_type(db, &def.ty, &roots[0], &ctx, &[0], &mut out, def.implicit_tags, true, 0) {
            let score = out.len();
            // A single labeled node means the type carried no structural
            // information (e.g. a bare ANY); such "matches" are noise.
            if score < 2 {
                continue;
            }
            let better = match &best {
                None => true,
                Some((s, id)) => score > *s || (score == *s && def.source > id.source),
            };
            if better {
                best = Some((
                    score,
                    Identification {
                        type_name: def.name.clone(),
                        source: def.source.clone(),
                        labels: out.into_iter().collect(),
                    },
                ));
            }
        }
    }
    let mut ident = best.map(|(_, ident)| ident)?;
    label_encapsulated(db, roots, &[], &mut ident.labels);
    Some(ident)
}

/// Recursively label the ASN.1 content nested inside encapsulating OCTET /
/// BIT STRING nodes. Each encapsulating node holds exactly one nested
/// item (the dumpasn1 heuristic, §5); it is identified independently and
/// its labels are re-keyed under the node's own path. The top-level match
/// never labels inside an encapsulation (OCTET/BIT STRING match as opaque
/// primitives), so there is nothing to overwrite; `or_insert` guards
/// against overlap regardless.
fn label_encapsulated(
    db: &SpecDb,
    nodes: &[Node],
    prefix: &[usize],
    labels: &mut HashMap<Vec<usize>, Label>,
) {
    for (i, node) in nodes.iter().enumerate() {
        let mut path = prefix.to_vec();
        path.push(i);
        if node.encapsulates {
            // `identify` recurses into deeper encapsulation itself, so we
            // don't re-descend into this node's children here.
            if let Some(sub) = identify(db, &node.children) {
                for (sub_path, label) in sub.labels {
                    let mut full = path.clone();
                    full.extend(sub_path);
                    labels.entry(full).or_insert(label);
                }
            }
        } else {
            label_encapsulated(db, &node.children, &path, labels);
        }
    }
}

fn kind_name(ty: &Type) -> String {
    match ty {
        Type::Sequence(_) | Type::SequenceOf(_) => "SEQUENCE".to_string(),
        Type::Set(_) | Type::SetOf(_) => "SET".to_string(),
        Type::Choice(_) => "CHOICE".to_string(),
        Type::Any => "ANY".to_string(),
        Type::Primitive(t) => crate::ber::universal_tag_name(*t).to_string(),
        Type::Reference(n) => n.clone(),
        Type::Tagged { number, .. } => format!("[{}]", number),
    }
}

fn commit(ctx: &Ctx, ty: &Type, path: &[usize], out: &mut Vec<(Vec<usize>, Label)>) {
    let type_name =
        if ctx.names.is_empty() { kind_name(ty) } else { ctx.names.join(".") };
    out.push((path.to_vec(), Label { field: ctx.field.clone(), type_name }));
}

/// Does `ty` resolve to an untagged CHOICE or ANY? (Such types cannot be
/// implicitly tagged; an IMPLICIT tag on them is treated as EXPLICIT.)
fn resolves_to_untagged(db: &SpecDb, ty: &Type, depth: usize) -> bool {
    if depth > MAX_RESOLVE_DEPTH {
        return false;
    }
    match ty {
        Type::Choice(_) | Type::Any => true,
        Type::Reference(name) => db
            .resolve(name)
            .is_some_and(|d| resolves_to_untagged(db, &d.ty, depth + 1)),
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn match_type(
    db: &SpecDb,
    ty: &Type,
    node: &Node,
    ctx: &Ctx,
    path: &[usize],
    out: &mut Vec<(Vec<usize>, Label)>,
    implicit_default: bool,
    check_tag: bool,
    depth: usize,
) -> bool {
    if depth > MAX_RESOLVE_DEPTH + 100 {
        return false;
    }
    match ty {
        Type::Reference(name) => {
            let Some(def) = db.resolve(name) else {
                // Unknown import: accept anything, like ANY.
                commit(ctx, ty, path, out);
                return true;
            };
            let mut ctx = ctx.clone();
            if ctx.names.last() != Some(name) {
                ctx.names.push(name.clone());
            }
            match_type(db, &def.ty, node, &ctx, path, out, def.implicit_tags, check_tag, depth + 1)
        }
        Type::Any => {
            commit(ctx, ty, path, out);
            true
        }
        Type::Primitive(tag) => {
            if check_tag && !(node.class == Class::Universal && node.tag == *tag) {
                return false;
            }
            commit(ctx, ty, path, out);
            true
        }
        Type::Sequence(fields) | Type::Set(fields) => {
            let want = if matches!(ty, Type::Sequence(_)) { TAG_SEQUENCE } else { TAG_SET };
            if check_tag && !(node.class == Class::Universal && node.tag == want) {
                return false;
            }
            if !node.constructed {
                return false;
            }
            commit(ctx, ty, path, out);
            match_fields(db, fields, node, path, out, implicit_default, depth)
        }
        Type::SequenceOf(elem) | Type::SetOf(elem) => {
            let want = if matches!(ty, Type::SequenceOf(_)) { TAG_SEQUENCE } else { TAG_SET };
            if check_tag && !(node.class == Class::Universal && node.tag == want) {
                return false;
            }
            if !node.constructed {
                return false;
            }
            commit(ctx, ty, path, out);
            for (i, child) in node.children.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(i);
                let ctx = Ctx::default();
                if !match_type(db, elem, child, &ctx, &child_path, out, implicit_default, true, depth + 1)
                {
                    return false;
                }
            }
            true
        }
        Type::Choice(alts) => {
            for alt in alts {
                let mark = out.len();
                let mut ctx = ctx.clone();
                ctx.names.push(alt.name.clone());
                if match_type(db, &alt.ty, node, &ctx, path, out, implicit_default, check_tag, depth + 1)
                {
                    return true;
                }
                out.truncate(mark);
            }
            false
        }
        Type::Tagged { class, number, mode, inner } => {
            if check_tag && !(node.class == *class && node.tag == *number) {
                return false;
            }
            let implicit = match mode {
                TagMode::Explicit => false,
                TagMode::Implicit => !resolves_to_untagged(db, inner, 0),
                TagMode::Default => {
                    implicit_default && !resolves_to_untagged(db, inner, 0)
                }
            };
            if implicit {
                match_type(db, inner, node, ctx, path, out, implicit_default, false, depth + 1)
            } else {
                // Explicit tags wrap exactly one element.
                if !node.constructed || node.children.len() != 1 {
                    return false;
                }
                commit(ctx, ty, path, out);
                let mut child_path = path.to_vec();
                child_path.push(0);
                let ctx = Ctx::default();
                match_type(db, inner, &node.children[0], &ctx, &child_path, out, implicit_default, true, depth + 1)
            }
        }
    }
}

/// Match SEQUENCE/SET components against the children of `node`, skipping
/// OPTIONAL/DEFAULT components as needed (with backtracking).
fn match_fields(
    db: &SpecDb,
    fields: &[Field],
    node: &Node,
    path: &[usize],
    out: &mut Vec<(Vec<usize>, Label)>,
    implicit_default: bool,
    depth: usize,
) -> bool {
    #[allow(clippy::too_many_arguments)]
    fn rec(
        db: &SpecDb,
        fields: &[Field],
        node: &Node,
        fi: usize,
        ci: usize,
        path: &[usize],
        out: &mut Vec<(Vec<usize>, Label)>,
        implicit_default: bool,
        depth: usize,
    ) -> bool {
        if fi == fields.len() {
            return ci == node.children.len();
        }
        let field = &fields[fi];
        if ci < node.children.len() {
            let mark = out.len();
            let mut child_path = path.to_vec();
            child_path.push(ci);
            let ctx = Ctx { field: Some(field.name.clone()), names: Vec::new() };
            if match_type(db, &field.ty, &node.children[ci], &ctx, &child_path, out, implicit_default, true, depth + 1)
                && rec(db, fields, node, fi + 1, ci + 1, path, out, implicit_default, depth)
            {
                return true;
            }
            out.truncate(mark);
        }
        if field.optional {
            return rec(db, fields, node, fi + 1, ci, path, out, implicit_default, depth);
        }
        false
    }
    rec(db, fields, node, 0, 0, path, out, implicit_default, depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::parse_forest;

    const MINI_SPEC: &str = r#"
        Mini { iso(1) test(99) } DEFINITIONS EXPLICIT TAGS ::=
        BEGIN
        -- a comment
        ub-max INTEGER ::= 64
        id-thing OBJECT IDENTIFIER ::= { iso(1) thing(2) 3 }

        Doc ::= SEQUENCE {
            version    [0] EXPLICIT INTEGER DEFAULT 1,
            serial     INTEGER,
            name       Label OPTIONAL,
            when       Timestamp,
            items      SEQUENCE SIZE (1..ub-max) OF Item }

        Label ::= UTF8String (SIZE (1..ub-max))
        Timestamp ::= CHOICE { utc UTCTime, general GeneralizedTime }
        Item ::= SEQUENCE { key OBJECT IDENTIFIER, value ANY DEFINED BY key OPTIONAL }
        END
    "#;

    fn mini_db() -> SpecDb {
        let mut db = SpecDb::default();
        db.add(parse_spec("mini", MINI_SPEC).unwrap());
        db
    }

    #[test]
    fn parses_mini_module() {
        let db = mini_db();
        assert_eq!(db.types.len(), 4);
        let doc = db.resolve("Doc").unwrap();
        assert!(!doc.implicit_tags);
        let Type::Sequence(fields) = &doc.ty else { panic!("Doc is a SEQUENCE") };
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].name, "version");
        assert!(fields[0].optional, "DEFAULT means the field may be absent");
        assert!(matches!(
            fields[0].ty,
            Type::Tagged { class: Class::ContextSpecific, number: 0, mode: TagMode::Explicit, .. }
        ));
        assert!(!fields[1].optional);
        assert_eq!(fields[2].ty, Type::Reference("Label".to_string()));
        assert!(matches!(fields[4].ty, Type::SequenceOf(_)));
        assert!(matches!(db.resolve("Timestamp").unwrap().ty, Type::Choice(_)));
    }

    /// DER for: SEQUENCE { [0]{INTEGER 2}, INTEGER 5, UTF8String "hi",
    /// UTCTime 260709115028Z, SEQUENCE { SEQUENCE { OID 2.5.4.3 } } }
    fn mini_doc() -> Vec<u8> {
        let mut v = vec![
            0xA0, 0x03, 0x02, 0x01, 0x02, // [0] { INTEGER 2 }
            0x02, 0x01, 0x05, // INTEGER 5
            0x0C, 0x02, b'h', b'i', // UTF8String
        ];
        v.extend_from_slice(b"\x17\x0d260709115028Z");
        v.extend_from_slice(&[0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03]);
        let mut doc = vec![0x30, v.len() as u8];
        doc.extend(v);
        doc
    }

    #[test]
    fn identifies_and_labels_document() {
        let db = mini_db();
        let roots = parse_forest(&mini_doc(), 0).unwrap();
        let ident = identify(&db, &roots).expect("document matches Doc");
        assert_eq!(ident.type_name, "Doc");
        let l = |path: &[usize]| ident.labels.get(path).unwrap();
        assert_eq!(l(&[0]).type_name, "Doc");
        assert_eq!(l(&[0, 0]).field.as_deref(), Some("version"));
        assert_eq!(l(&[0, 0, 0]).type_name, "INTEGER");
        assert_eq!(l(&[0, 1]).field.as_deref(), Some("serial"));
        assert_eq!(l(&[0, 2]).field.as_deref(), Some("name"));
        assert_eq!(l(&[0, 2]).type_name, "Label");
        assert_eq!(l(&[0, 3]).type_name, "Timestamp.utc");
        assert_eq!(l(&[0, 4]).field.as_deref(), Some("items"));
        assert_eq!(l(&[0, 4, 0]).type_name, "Item");
        assert_eq!(l(&[0, 4, 0, 0]).field.as_deref(), Some("key"));
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let db = mini_db();
        // Same document without [0] version and without the name.
        let mut v = vec![0x02, 0x01, 0x05];
        v.extend_from_slice(b"\x17\x0d260709115028Z");
        v.extend_from_slice(&[0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03]);
        let mut doc = vec![0x30, v.len() as u8];
        doc.extend(v);
        let roots = parse_forest(&doc, 0).unwrap();
        let ident = identify(&db, &roots).expect("matches without optional fields");
        assert_eq!(ident.type_name, "Doc");
        assert_eq!(ident.labels.get(&vec![0, 0]).unwrap().field.as_deref(), Some("serial"));
    }

    #[test]
    fn mismatch_is_rejected() {
        let db = mini_db();
        // serial (mandatory INTEGER) replaced by a BOOLEAN.
        let mut v = vec![0x01, 0x01, 0xFF];
        v.extend_from_slice(b"\x17\x0d260709115028Z");
        v.extend_from_slice(&[0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03]);
        let mut doc = vec![0x30, v.len() as u8];
        doc.extend(v);
        let roots = parse_forest(&doc, 0).unwrap();
        assert!(identify(&db, &roots).is_none());
    }

    #[test]
    fn implicit_tags_default() {
        let spec = r#"
            M DEFINITIONS IMPLICIT TAGS ::= BEGIN
            T ::= SEQUENCE { a [0] INTEGER, b [1] EXPLICIT INTEGER }
            END
        "#;
        let mut db = SpecDb::default();
        db.add(parse_spec("m", spec).unwrap());
        // a: implicit [0] primitive; b: explicit [1] wrapping INTEGER.
        let data = [0x30, 0x08, 0x80, 0x01, 0x2A, 0xA1, 0x03, 0x02, 0x01, 0x07];
        let roots = parse_forest(&data, 0).unwrap();
        let ident = identify(&db, &roots).expect("matches T");
        assert_eq!(ident.type_name, "T");
        assert_eq!(ident.labels.get(&vec![0, 0]).unwrap().field.as_deref(), Some("a"));
        assert_eq!(ident.labels.get(&vec![0, 1]).unwrap().field.as_deref(), Some("b"));
    }
}
