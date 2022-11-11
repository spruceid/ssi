use std::collections::hash_map::Iter as HashMapIter;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Write;
use std::iter::Peekable;
use std::str::Chars;
use std::str::FromStr;

use chrono::prelude::{DateTime, Utc};
use iref::IriBuf;

use crate::error::Error;

// https://json-ld.github.io/rdf-dataset-canonicalization/spec/
// https://www.w3.org/TR/n-quads/#terminals

/// <https://www.w3.org/TR/rdf11-concepts/#dfn-rdf-dataset>
#[derive(Debug, Clone, Default)]
pub struct DataSet {
    pub default_graph: Graph,
    pub named_graphs: HashMap<GraphLabel, Graph>,
}

/// <https://www.w3.org/TR/rdf11-concepts/#dfn-rdf-graph>
#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub triples: Vec<Triple>,
}

/// Reference to a [Graph]
#[derive(Debug, Clone, Default)]
pub struct GraphRef<'a> {
    pub triples: Vec<&'a Triple>,
}

/// <https://www.w3.org/TR/rdf11-concepts/#dfn-rdf-triple>
#[derive(Debug, Clone)]
pub struct Triple {
    pub subject: Subject,
    pub predicate: Predicate,
    pub object: Object,
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub subject: Subject,
    pub predicate: Predicate,
    pub object: Object,
    pub graph_label: Option<GraphLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    IRIRef(IRIRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
    Literal(Literal),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphLabel {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IRIRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlankNodeLabel(pub String);

#[derive(Debug, Clone)]
pub enum IRIOrBlankNodeIdentifier {
    IRIRef(IRIRef),
    BlankNodeLabel(BlankNodeLabel),
}

pub const LANG_STRING_IRI_STR: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteral(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lang(pub String);

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
                    let _ = write!(out, "\\u{:#04x}", bytes);
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

fn parse_lang_subtag(chars: &mut Peekable<Chars>, string: &mut String) -> Result<(), Error> {
    for c in chars {
        match c {
            'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n'
            | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z' | 'A' | 'B'
            | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O' | 'P'
            | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z' | '0' | '1' | '2' | '3'
            | '4' | '5' | '6' | '7' | '8' | '9' => {
                string.push(c);
            }
            ' ' | '\t' => break,
            _ => return Err(Error::ExpectedLang),
        }
    }
    Ok(())
}

fn parse_lang(chars: &mut Peekable<Chars>) -> Result<Lang, Error> {
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n'
            | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z' | 'A' | 'B'
            | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O' | 'P'
            | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z' => {
                out.push(c);
            }
            '-' => {
                out.push(c);
                parse_lang_subtag(chars, &mut out)?;
            }
            ' ' | '\t' => break,
            _ => return Err(Error::ExpectedLang),
        }
    }
    Ok(Lang(out))
}

impl From<&Lang> for String {
    fn from(lang: &Lang) -> String {
        lang.0.clone()
    }
}

impl FromStr for Lang {
    type Err = Error;
    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut chars = line.chars().peekable();
        let lang = parse_lang(&mut chars)?;
        if chars.peek().is_some() {
            return Err(Error::ExpectedLang);
        }
        Ok(lang)
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

impl TryFrom<String> for IRIRef {
    type Error = Error;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        IriBuf::new(&string)?;
        Ok(Self(string))
    }
}

impl TryFrom<String> for IRIOrBlankNodeIdentifier {
    type Error = Error;
    fn try_from(id: String) -> Result<Self, Self::Error> {
        // TODO: check if well-formed
        // https://w3c.github.io/json-ld-api/#dfn-well-formed
        let first_char = id.chars().next();
        match first_char {
            Some('_') => Ok(Self::BlankNodeLabel(BlankNodeLabel(id))),
            Some(_) => Ok(Self::IRIRef(IRIRef::try_from(id)?)),
            None => Err(Error::ExpectedString),
        }
    }
}

impl From<IRIOrBlankNodeIdentifier> for GraphLabel {
    fn from(graph_name: IRIOrBlankNodeIdentifier) -> Self {
        match graph_name {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(id) => Self::BlankNodeLabel(id),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Self::IRIRef(id),
        }
    }
}

impl From<IRIOrBlankNodeIdentifier> for Object {
    fn from(object: IRIOrBlankNodeIdentifier) -> Self {
        match object {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(id) => Self::BlankNodeLabel(id),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Self::IRIRef(id),
        }
    }
}

impl TryFrom<String> for GraphLabel {
    type Error = Error;
    fn try_from(graph_label: String) -> Result<Self, Self::Error> {
        Ok(match IRIOrBlankNodeIdentifier::try_from(graph_label)? {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(id) => Self::BlankNodeLabel(id),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Self::IRIRef(id),
        })
    }
}

impl TryFrom<String> for Subject {
    type Error = Error;
    fn try_from(subject: String) -> Result<Self, Self::Error> {
        Ok(match IRIOrBlankNodeIdentifier::try_from(subject)? {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(id) => Self::BlankNodeLabel(id),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Self::IRIRef(id),
        })
    }
}

impl TryFrom<String> for Object {
    type Error = Error;
    fn try_from(object: String) -> Result<Self, Self::Error> {
        // TODO: detect Literal
        Ok(match IRIOrBlankNodeIdentifier::try_from(object)? {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(id) => Self::BlankNodeLabel(id),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Self::IRIRef(id),
        })
    }
}

impl TryFrom<IRIOrBlankNodeIdentifier> for Predicate {
    type Error = Error;
    fn try_from(id: IRIOrBlankNodeIdentifier) -> Result<Self, Self::Error> {
        match id {
            IRIOrBlankNodeIdentifier::BlankNodeLabel(_) => Err(Error::UnsupportedBlankPredicate),
            IRIOrBlankNodeIdentifier::IRIRef(id) => Ok(Self::IRIRef(id)),
        }
    }
}

impl Triple {
    pub fn matches(
        &self,
        subject_opt: Option<&Subject>,
        predicate_opt: Option<&Predicate>,
        object_opt: Option<&Object>,
    ) -> bool {
        if let Some(subject) = subject_opt {
            if subject != &self.subject {
                return false;
            }
        }
        if let Some(predicate) = predicate_opt {
            if predicate != &self.predicate {
                return false;
            }
        }
        if let Some(object) = object_opt {
            if object != &self.object {
                return false;
            }
        }
        true
    }
}

impl Statement {
    pub fn blank_node_components(&self) -> Vec<&BlankNodeLabel> {
        self.blank_node_components_with_position()
            .into_iter()
            .map(|(label, _position)| label)
            .collect()
    }

    pub fn blank_node_components_mut(&mut self) -> Vec<&mut BlankNodeLabel> {
        let mut labels: Vec<&mut BlankNodeLabel> = Vec::new();
        if let Subject::BlankNodeLabel(ref mut label) = self.subject {
            labels.push(label)
        }
        if let Object::BlankNodeLabel(ref mut label) = self.object {
            labels.push(label)
        }
        if let Some(GraphLabel::BlankNodeLabel(ref mut label)) = self.graph_label {
            labels.push(label)
        }
        labels
    }

    pub fn blank_node_components_with_position(&self) -> Vec<(&BlankNodeLabel, char)> {
        let mut labels = Vec::new();
        if let Subject::BlankNodeLabel(ref label) = self.subject {
            labels.push((label, 's'))
        }
        if let Object::BlankNodeLabel(ref label) = self.object {
            labels.push((label, 'o'))
        }
        if let Some(GraphLabel::BlankNodeLabel(ref label)) = self.graph_label {
            labels.push((label, 'g'))
        }
        labels
    }
}

pub struct DataSetGraphIter<'a> {
    dataset: &'a DataSet,
    named_graphs_iter: Option<HashMapIter<'a, GraphLabel, Graph>>,
}

impl<'a> Iterator for DataSetGraphIter<'a> {
    type Item = (Option<&'a GraphLabel>, &'a Graph);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut named_graphs_iter) = self.named_graphs_iter {
            named_graphs_iter
                .next()
                .map(|(graph_label, graph)| (Some(graph_label), graph))
        } else {
            self.named_graphs_iter = Some(self.dataset.named_graphs.iter());
            Some((None, &self.dataset.default_graph))
        }
    }
}

impl DataSet {
    pub fn add(&mut self, graph_name: GraphLabel, graph: Graph) {
        self.named_graphs.insert(graph_name, graph);
    }

    pub fn iterable(&self) -> DataSetGraphIter {
        DataSetGraphIter {
            dataset: self,
            named_graphs_iter: None,
        }
    }

    pub fn statements(&self) -> Vec<Statement> {
        let graphs = self.iterable();
        graphs
            .flat_map(|(graph_name, graph)| {
                graph.triples.iter().cloned().map(move |triple| Statement {
                    subject: triple.subject,
                    predicate: triple.predicate,
                    object: triple.object,
                    graph_label: graph_name.cloned(),
                })
            })
            .collect()
    }

    pub fn add_statement(&mut self, statement: Statement) {
        let graph = match statement.graph_label {
            Some(label) => self
                .named_graphs
                .entry(label)
                .or_insert_with(Graph::default),
            None => &mut self.default_graph,
        };
        graph.add(Triple {
            subject: statement.subject,
            predicate: statement.predicate,
            object: statement.object,
        });
    }

    pub fn to_nquads(&self) -> Result<String, Error> {
        // https://www.w3.org/TR/n-quads/
        let mut lines = self
            .statements()
            .iter()
            .map(|statement| statement.into())
            .collect::<Vec<String>>();
        lines.sort();
        lines.dedup();
        Ok(lines.join(""))
    }

    pub fn to_nquads_vec(&self) -> Result<Vec<String>, Error> {
        // https://www.w3.org/TR/n-quads/
        let mut lines = self
            .statements()
            .iter()
            .map(|statement| statement.into())
            .collect::<Vec<String>>();
        lines.sort();
        lines.dedup();
        Ok(lines)
    }
}

impl Graph {
    pub fn iterable(&self) -> std::slice::Iter<'_, Triple> {
        self.triples.iter()
    }

    pub fn add(&mut self, triple: Triple) {
        self.triples.push(triple);
    }

    pub fn as_ref(&self) -> GraphRef {
        GraphRef {
            triples: self.triples.iter().collect(),
        }
    }
}

impl<'a> GraphRef<'a> {
    /// Remove triple matching given terms
    pub fn take(
        &mut self,
        subject_opt: Option<&Subject>,
        predicate_opt: Option<&Predicate>,
        object_opt: Option<&Object>,
    ) -> Option<&'a Triple> {
        for (i, element) in self.triples.iter().enumerate() {
            if element.matches(subject_opt, predicate_opt, object_opt) {
                return Some(self.triples.swap_remove(i));
            }
        }
        None
    }

    /// Given a string, assert that a statement exists with the given subject, predicate and string
    /// as object (IRI), and remove it; or given no string, assert that no statement with given
    /// subject and predicate exists.
    pub fn match_iri_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        object_opt_expected: Option<&str>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        let object_iri_opt = match triple_opt {
            None => None,
            Some(triple) => match &triple.object {
                Object::IRIRef(IRIRef(iri)) => Some(iri),
                _ => return Err(Error::UnexpectedTriple(triple.clone())),
            },
        };
        match (object_iri_opt, object_opt_expected) {
            (None, None) => {}
            (Some(object), Some(object_expected)) => {
                if object != object_expected {
                    return Err(Error::ObjectMismatch(
                        predicate_iri.to_string(),
                        object_expected.to_string(),
                        object.to_string(),
                    ));
                }
            }
            (None, Some(object_expected)) => {
                return Err(Error::ExpectedObjectForPredicate(
                    predicate_iri.to_string(),
                    object_expected.to_string(),
                ));
            }
            (Some(object), None) => {
                return Err(Error::UnexpectedObjectForPredicate(
                    predicate_iri.to_string(),
                    object.to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Given a string, assert that a statement exists with the given subject, predicate and string
    /// as object (IRI or String), and remove it; or given no string, assert that no statement with
    /// given subject and predicate exists.
    pub fn match_iri_or_string_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        object_opt_expected: Option<&str>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        let object_opt = match triple_opt {
            None => None,
            Some(triple) => match &triple.object {
                Object::IRIRef(IRIRef(iri)) => Some(iri),
                Object::Literal(Literal::String {
                    string: StringLiteral(string_literal),
                }) => Some(string_literal),
                _ => return Err(Error::UnexpectedTriple(triple.clone())),
            },
        };
        match (object_opt, object_opt_expected) {
            (None, None) => {}
            (Some(object), Some(object_expected)) => {
                if object != object_expected {
                    return Err(Error::ObjectMismatch(
                        predicate_iri.to_string(),
                        object_expected.to_string(),
                        object.to_string(),
                    ));
                }
            }
            (None, Some(object_expected)) => {
                return Err(Error::ExpectedObjectForPredicate(
                    predicate_iri.to_string(),
                    object_expected.to_string(),
                ));
            }
            (Some(object), None) => {
                return Err(Error::UnexpectedObjectForPredicate(
                    predicate_iri.to_string(),
                    object.to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Given a date-time, assert that a statement exists with the given subject, predicate and
    /// object, and remove it; or given no object, assert that no statement with given subject and
    /// predicate exists.
    pub fn match_date_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        value_opt: Option<&DateTime<Utc>>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        match (value_opt, triple_opt) {
            (None, None) => {}
            (None, Some(triple)) => {
                return Err(Error::UnexpectedTriple(triple.clone()));
            }
            (Some(_value), None) => {
                return Err(Error::MissingStatement);
            }
            (Some(datetime), Some(triple)) => {
                let object_datetime = match &triple.object {
                    Object::Literal(Literal::Typed {
                        string: StringLiteral(string_literal),
                        type_: IRIRef(type_iri),
                    }) if type_iri == "http://www.w3.org/2001/XMLSchema#dateTime" => {
                        DateTime::parse_from_rfc3339(string_literal)
                            .map_err(|_| Error::UnexpectedTriple(triple.clone()))?
                    }
                    _ => return Err(Error::UnexpectedTriple(triple.clone())),
                };
                if datetime != &object_datetime {
                    return Err(Error::UnexpectedTriple(triple.clone()));
                }
            }
        }
        Ok(())
    }

    /// Given a multibase-encoded string, assert that a statement exists with the given subject, predicate and
    /// object, and remove it; or given no object, assert that no statement with given subject and
    /// predicate exists.
    pub fn match_multibase_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        value_opt: Option<&serde_json::Value>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        match (value_opt, triple_opt) {
            (None, None) => {}
            (Some(_value), None) => {
                return Err(Error::MissingStatement);
            }
            (Some(serde_json::Value::String(value_string)), Some(triple)) => {
                let object_str = match &triple.object {
                    Object::Literal(Literal::Typed {
                        string: StringLiteral(string_literal),
                        type_: IRIRef(type_iri),
                    }) if type_iri == "https://w3id.org/security#multibase" => string_literal,
                    _ => return Err(Error::UnexpectedTriple(triple.clone())),
                };
                if value_string != object_str {
                    return Err(Error::UnexpectedTriple(triple.clone()));
                }
            }
            (_, Some(triple)) => {
                return Err(Error::UnexpectedTriple(triple.clone()));
            }
        }
        Ok(())
    }

    /// Given a JSON object, assert that a statement exists with the given subject, predicate and
    /// object, and remove it; or given no object, assert that no statement with given subject and
    /// predicate exists.
    pub fn match_json_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        value_opt: Option<&serde_json::Value>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        match (value_opt, triple_opt) {
            (None, None) => {}
            (None, Some(triple)) => {
                return Err(Error::UnexpectedTriple(triple.clone()));
            }
            (Some(_value), None) => {
                return Err(Error::MissingStatement);
            }
            (Some(value), Some(triple)) => {
                let object_value: serde_json::Value = match &triple.object {
                    Object::Literal(Literal::Typed {
                        string: StringLiteral(string_literal),
                        type_: IRIRef(type_iri),
                    }) if type_iri == "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON" => {
                        serde_json::from_str(string_literal)?
                    }
                    _ => return Err(Error::UnexpectedTriple(triple.clone())),
                };
                if value != &object_value {
                    return Err(Error::UnexpectedTriple(triple.clone()));
                }
            }
        }
        Ok(())
    }

    /// Given a JSON array value, assert that a statement exists with the given subject, predicate
    /// and list id as object, and subsequent statements exist for the list values corresponding to
    /// the given array. Remove all these matching statements from the graph reference.  If given
    /// no JSON value, assert that no statement with given subject and predicate exists in the
    /// graph reference.
    pub fn match_list_property(
        &mut self,
        subject: &Subject,
        predicate_iri: &str,
        value_opt: Option<&serde_json::Value>,
    ) -> Result<(), Error> {
        let triple_opt = self.take(
            Some(subject),
            Some(&Predicate::IRIRef(IRIRef(predicate_iri.to_string()))),
            None,
        );
        match (value_opt, triple_opt) {
            (None, None) => {}
            (None, Some(triple)) => {
                return Err(Error::UnexpectedTriple(triple.clone()));
            }
            (Some(_value), None) => {
                return Err(Error::MissingStatement);
            }
            (Some(value), Some(mut triple)) => {
                let array_vec = value.as_array().ok_or(Error::ExpectedArray)?;
                let mut array_iter = array_vec.iter();
                // Iterate through list and match it with array values.
                // More info about lists in JSON-LD/RDF: https://www.w3.org/TR/json-ld11/#lists
                while triple.object
                    != Object::IRIRef(IRIRef(
                        "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil".to_string(),
                    ))
                {
                    let item_id = match triple.object {
                        Object::BlankNodeLabel(ref bn) => Subject::BlankNodeLabel(bn.clone()),
                        _ => return Err(Error::UnexpectedTriple(triple.clone())),
                    };
                    let item_triple = self
                        .take(
                            Some(&item_id),
                            Some(&Predicate::IRIRef(IRIRef(
                                "http://www.w3.org/1999/02/22-rdf-syntax-ns#first".to_string(),
                            ))),
                            None,
                        )
                        .ok_or(Error::ExpectedListValue)?;
                    let item_object = match item_triple.object {
                        Object::IRIRef(IRIRef(ref iri)) => iri,
                        _ => return Err(Error::UnexpectedTriple(item_triple.clone())),
                    };
                    let value = array_iter.next().ok_or(Error::ExpectedEndOfList)?;
                    if item_object != value {
                        return Err(Error::ListItemMismatch(
                            item_object.to_string(),
                            value.to_string(),
                        ));
                    }
                    triple = self
                        .take(
                            Some(&item_id),
                            Some(&Predicate::IRIRef(IRIRef(
                                "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest".to_string(),
                            ))),
                            None,
                        )
                        .ok_or(Error::ExpectedRestOfList)?;
                }
                if array_iter.next().is_some() {
                    return Err(Error::UnexpectedEndOfList);
                }
            }
        }
        Ok(())
    }
}

impl From<DateTime<Utc>> for Literal {
    fn from(date_time: DateTime<Utc>) -> Self {
        Literal::Typed {
            string: StringLiteral(date_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
            type_: IRIRef("http://www.w3.org/2001/XMLSchema#dateTime".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_uchar(chars: &mut Peekable<Chars>, len: usize) -> Result<char, Error> {
        let escaped: String = chars.take(len).collect();
        char::try_from(u32::from_str_radix(&escaped, 16).map_err(|_| Error::ExpectedString)?)
            .map_err(|_| Error::ExpectedString)
    }

    fn parse_iri_ref(chars: &mut Peekable<Chars>) -> Result<IRIRef, Error> {
        let mut out = String::new();
        if chars.next() != Some('<') {
            return Err(Error::ExpectedIRIRef);
        }
        while let Some(c) = chars.next() {
            match c {
                '>' => return Ok(IRIRef(out)),
                '\\' => {
                    let c = match chars.next() {
                        Some('u') => parse_uchar(chars, 4)?,
                        Some('U') => parse_uchar(chars, 8)?,
                        _ => return Err(Error::ExpectedIRIRef),
                    };
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
        Err(Error::ExpectedIRIRef)
    }

    fn parse_string_literal_quote(chars: &mut Peekable<Chars>) -> Result<StringLiteral, Error> {
        let mut string = String::new();
        if chars.next() != Some('"') {
            return Err(Error::ExpectedLiteral);
        }
        while let Some(c) = chars.next() {
            match c {
                '"' => return Ok(StringLiteral(string)),
                '\\' => {
                    let c = match chars.next() {
                        Some('u') => parse_uchar(chars, 4)?,
                        Some('U') => parse_uchar(chars, 8)?,
                        Some('t') => '\t',
                        Some('b') => '\x08',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('f') => '\x0c',
                        Some('"') => '"',
                        Some('\'') => '\'',
                        Some('\\') => '\\',
                        _ => return Err(Error::ExpectedLiteral),
                    };
                    string.push(c);
                }
                _ => string.push(c),
            }
        }
        Err(Error::ExpectedLiteral)
    }

    fn parse_literal(chars: &mut Peekable<Chars>) -> Result<Literal, Error> {
        let string = parse_string_literal_quote(chars)?;
        match chars.peek() {
            Some(' ') | Some('\t') | None => Ok(Literal::String { string }),
            Some('^') => {
                chars.next();
                if chars.next() != Some('^') {
                    return Err(Error::ExpectedLiteral);
                }
                let type_ = parse_iri_ref(chars)?;
                Ok(Literal::Typed { string, type_ })
            }
            Some('@') => {
                chars.next();
                let lang = parse_lang(chars)?;
                Ok(Literal::LangTagged { string, lang })
            }
            _ => Err(Error::ExpectedLiteral),
        }
    }

    fn parse_blank_node_label(chars: &mut Peekable<Chars>) -> Result<BlankNodeLabel, Error> {
        if chars.next() != Some('_') {
            return Err(Error::ExpectedBlankNodeLabel);
        }
        if chars.next() != Some(':') {
            return Err(Error::ExpectedBlankNodeLabel);
        }
        let mut out = String::new();
        out.push_str("_:");
        for c in chars.by_ref() {
            match c {
                ' ' => break,
                '\t' => break,
                // TODO: handle PN_CHARS*
                // https://www.w3.org/TR/n-quads/#grammar-production-BLANK_NODE_LABEL
                _ => out.push(c),
            }
        }
        Ok(BlankNodeLabel(out.to_string()))
    }

    fn parse_subject(chars: &mut Peekable<Chars>) -> Result<Subject, Error> {
        match chars.peek() {
            Some('<') => Ok(Subject::IRIRef(parse_iri_ref(chars)?)),
            Some('_') => Ok(Subject::BlankNodeLabel(parse_blank_node_label(chars)?)),
            _ => Err(Error::ExpectedTerm),
        }
    }

    fn parse_predicate(chars: &mut Peekable<Chars>) -> Result<Predicate, Error> {
        Ok(Predicate::IRIRef(parse_iri_ref(chars)?))
    }

    fn parse_object(chars: &mut Peekable<Chars>) -> Result<Object, Error> {
        match chars.peek() {
            Some('"') => Ok(Object::Literal(parse_literal(chars)?)),
            Some('<') => Ok(Object::IRIRef(parse_iri_ref(chars)?)),
            Some('_') => Ok(Object::BlankNodeLabel(parse_blank_node_label(chars)?)),
            _ => Err(Error::ExpectedTerm),
        }
    }

    fn parse_graph_label(chars: &mut Peekable<Chars>) -> Result<Option<GraphLabel>, Error> {
        match chars.peek() {
            Some('<') => Ok(Some(GraphLabel::IRIRef(parse_iri_ref(chars)?))),
            Some('_') => Ok(Some(GraphLabel::BlankNodeLabel(parse_blank_node_label(
                chars,
            )?))),
            Some(_) => Err(Error::ExpectedTerm),
            None => Ok(None),
        }
    }

    fn ignore_whitespace(chars: &mut Peekable<Chars>) {
        while let Some(c) = chars.peek() {
            match c {
                ' ' | '\t' => {
                    chars.next();
                }
                _ => break,
            }
        }
    }

    impl FromStr for Statement {
        type Err = Error;
        fn from_str(line: &str) -> Result<Self, Self::Err> {
            let mut chars = line.chars().peekable();
            if chars.next_back() != Some('.') {
                return Err(Error::ExpectedNQuad);
            }
            match chars.next_back() {
                Some(' ') | Some('\t') => {}
                _ => return Err(Error::ExpectedNQuad),
            }
            let subject = parse_subject(&mut chars)?;
            ignore_whitespace(&mut chars);
            let predicate = parse_predicate(&mut chars)?;
            ignore_whitespace(&mut chars);
            let object = parse_object(&mut chars)?;
            ignore_whitespace(&mut chars);
            let graph_label = parse_graph_label(&mut chars)?;
            Ok(Self {
                subject,
                predicate,
                object,
                graph_label,
            })
        }
    }

    // Parse N-Quads for testing in urdna2015
    impl FromStr for DataSet {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut dataset = DataSet::default();
            for line in s.lines() {
                let statement = Statement::from_str(line)?;
                dataset.add_statement(statement);
            }
            Ok(dataset)
        }
    }

    #[test]
    fn escape() {
        let string_literal = StringLiteral("\t\x08\n\r\x0c\"\'\\\u{221e}".to_string());
        assert_eq!(
            String::from(&string_literal),
            "\"\t\x08\\n\\r\x0c\\\"'\\\\\u{221e}\""
        );

        // Awaiting https://github.com/json-ld/rdf-dataset-canonicalization/issues/15
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
