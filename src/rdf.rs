use chrono::prelude::{DateTime, Utc};

use crate::error::Error;

// https://json-ld.github.io/normalization/spec/
// https://www.w3.org/TR/n-quads/#terminals

#[derive(Debug, Clone)]
pub struct DataSet {
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub subject: Subject,
    pub predicate: Predicate,
    pub object: Object,
    pub graph_label: Option<GraphLabel>,
}

#[derive(Debug, Clone)]
pub enum Subject {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
}

#[derive(Debug, Clone)]
pub enum Predicate {
    IRIRef(IRIRef),
}

#[derive(Debug, Clone)]
pub enum Object {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
    Literal(Literal),
}

#[derive(Debug, Clone)]
pub enum GraphLabel {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
}

#[derive(Debug, Clone)]
pub struct IRIRef(pub String);

#[derive(Debug, Clone)]
pub struct BlankNodeLabel(pub String);

#[derive(Debug, Clone)]
pub enum Literal {
    String {
        string: StringLiteral,
    },
    Typed {
        string: StringLiteral,
        type_: IRIRef,
    },
    LangTagged {
        string: StringLiteral,
        lang: Lang,
    },
}

#[derive(Debug, Clone)]
pub struct StringLiteral(pub String);

#[derive(Debug, Clone)]
pub struct Lang(String);

impl Default for DataSet {
    fn default() -> Self {
        DataSet {
            statements: Vec::default(),
        }
    }
}

impl From<&Statement> for String {
    fn from(statement: &Statement) -> String {
        String::from(&statement.subject)
            + " "
            + &String::from(&statement.predicate)
            + " "
            + &String::from(&statement.object)
            + &match &statement.graph_label {
                Some(graph_label) => " ".to_string() + &String::from(graph_label),
                None => "".to_string(),
            }
            + " .\n"
    }
}

impl From<&Subject> for String {
    fn from(subject: &Subject) -> String {
        match subject {
            Subject::IRIRef(iri_ref) => String::from(iri_ref),
            Subject::BlankNodeLabel(blank_node_label) => String::from(blank_node_label),
        }
    }
}

impl From<&Predicate> for String {
    fn from(predicate: &Predicate) -> String {
        match predicate {
            Predicate::IRIRef(iri_ref) => String::from(iri_ref),
        }
    }
}

impl From<&Object> for String {
    fn from(object: &Object) -> String {
        match object {
            Object::IRIRef(iri_ref) => String::from(iri_ref),
            Object::BlankNodeLabel(blank_node_label) => String::from(blank_node_label),
            Object::Literal(literal) => String::from(literal),
        }
    }
}

impl From<&GraphLabel> for String {
    fn from(graph_label: &GraphLabel) -> String {
        match graph_label {
            GraphLabel::IRIRef(iri_ref) => String::from(iri_ref),
            GraphLabel::BlankNodeLabel(blank_node_label) => String::from(blank_node_label),
        }
    }
}

impl From<&IRIRef> for String {
    fn from(iri_ref: &IRIRef) -> String {
        let string = &iri_ref.0;
        let mut out = String::with_capacity(string.len() + 6);
        out.push('<');
        for c in string.chars() {
            match c {
                '\x00'..='\x20' | '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\' => {
                    let bytes: u32 = c.into();
                    out.push_str(&format!("\\u{:#04x}", bytes))
                }
                _ => out.push(c),
            }
        }
        out.push('>');
        out
    }
}

impl From<&StringLiteral> for String {
    fn from(string_literal: &StringLiteral) -> String {
        let string = &string_literal.0;
        // estimate size of escaped string
        let mut out = String::with_capacity(string.len() + 6);
        out.push('"');
        for c in string.chars() {
            match c {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }
}

impl From<&BlankNodeLabel> for String {
    fn from(blank_node_label: &BlankNodeLabel) -> String {
        // Escaping not implemented, since we are constructing these
        blank_node_label.0.clone()
    }
}

impl From<&Lang> for String {
    fn from(lang: &Lang) -> String {
        // TODO: use TryFrom and error if invalid
        // [a-zA-Z]+ ('-' [a-zA-Z0-9]+)*
        lang.0.clone()
    }
}

impl From<&Literal> for String {
    fn from(literal: &Literal) -> String {
        match literal {
            Literal::String { string } => String::from(string),
            Literal::Typed { string, type_ } => String::from(string) + "^^" + &String::from(type_),
            Literal::LangTagged { string, lang } => {
                String::from(string) + "@" + &String::from(lang)
            }
        }
    }
}

impl DataSet {
    pub fn to_nquads(&self) -> Result<String, Error> {
        let mut lines = self
            .statements
            .iter()
            .map(|statement| statement.into())
            .collect::<Vec<String>>();
        lines.sort();
        Ok(lines.join(""))
    }
}

impl From<DateTime<Utc>> for Literal {
    fn from(date_time: DateTime<Utc>) -> Self {
        Literal::Typed {
            string: StringLiteral(format!("{}", date_time.format("%Y-%m-%dT%H:%M:%SZ"))),
            type_: IRIRef("http://www.w3.org/2001/XMLSchema#dateTime".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape() {
        let string_literal = StringLiteral("\t\x08\n\r\x0c\"\'\\\u{221e}".to_string());
        assert_eq!(
            String::from(&string_literal),
            "\"\t\x08\\n\\r\x0c\\\"'\\\\\u{221e}\""
        );

        // Awaiting https://github.com/json-ld/normalization/issues/15
        // for adding tests of IRI ref escaping
        let iri_ref = IRIRef("urn:ex:s".to_string());
        assert_eq!(String::from(&iri_ref), "<urn:ex:s>");
    }

    #[test]
    fn line() {
        let statement = Statement {
            subject: Subject::BlankNodeLabel(BlankNodeLabel("_:c14n0".to_string())),
            predicate: Predicate::IRIRef(IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
            )),
            object: Object::IRIRef(IRIRef("http://example.org/vocab#Foo".to_string())),
            graph_label: None,
        };
        assert_eq!(String::from(&statement), "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab#Foo> .\n");
    }
}
