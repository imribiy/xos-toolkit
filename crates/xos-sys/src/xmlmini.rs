use std::collections::HashMap;

pub(crate) struct Element {
    pub local: String,
    pub ns: String,
    pub children: Vec<Element>,
    pub text: String,
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

fn decode_entities(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let semi = tail.find(';').ok_or("bad entity")?;
        let ent = &tail[1..semi];
        let ch = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ if ent.starts_with("#x") => {
                char::from_u32(u32::from_str_radix(&ent[2..], 16).map_err(|_| "bad entity")?)
                    .ok_or("bad entity")?
            }
            _ if ent.starts_with('#') => {
                char::from_u32(ent[1..].parse::<u32>().map_err(|_| "bad entity")?)
                    .ok_or("bad entity")?
            }
            _ => return Err("unknown entity".into()),
        };
        out.push(ch);
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn skip_ws(&mut self) {
        let r = self.rest();
        self.pos += r.len() - r.trim_start().len();
    }

    fn skip_misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_ws();
            let r = self.rest();
            if r.starts_with("<?") {
                let end = r.find("?>").ok_or("unterminated pi")?;
                self.pos += end + 2;
            } else if r.starts_with("<!--") {
                let end = r.find("-->").ok_or("unterminated comment")?;
                self.pos += end + 3;
            } else if r.starts_with("<!") {
                return Err("DTD is prohibited".into());
            } else {
                return Ok(());
            }
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let r = self.rest();
        let end = r
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/' || c == '=')
            .unwrap_or(r.len());
        if end == 0 {
            return Err("name expected".into());
        }
        self.pos += end;
        Ok(r[..end].to_string())
    }

    fn element(&mut self, scopes: &mut Vec<HashMap<String, String>>) -> Result<Element, String> {
        if !self.rest().starts_with('<') {
            return Err("element expected".into());
        }
        self.pos += 1;
        let qname = self.name()?;
        let mut attrs: Vec<(String, String)> = Vec::new();
        let self_closing;
        loop {
            self.skip_ws();
            let r = self.rest();
            if r.starts_with("/>") {
                self.pos += 2;
                self_closing = true;
                break;
            }
            if r.starts_with('>') {
                self.pos += 1;
                self_closing = false;
                break;
            }
            let an = self.name()?;
            self.skip_ws();
            if !self.rest().starts_with('=') {
                return Err("= expected".into());
            }
            self.pos += 1;
            self.skip_ws();
            let r = self.rest();
            let q = r.chars().next().ok_or("quote expected")?;
            if q != '"' && q != '\'' {
                return Err("quote expected".into());
            }
            let body = &r[1..];
            let end = body.find(q).ok_or("unterminated attribute")?;
            attrs.push((an, decode_entities(&body[..end])?));
            self.pos += end + 2;
        }
        let mut scope = HashMap::new();
        for (n, v) in &attrs {
            if n == "xmlns" {
                scope.insert(String::new(), v.clone());
            } else if let Some(p) = n.strip_prefix("xmlns:") {
                scope.insert(p.to_string(), v.clone());
            }
        }
        scopes.push(scope);
        let (prefix, local) = match qname.split_once(':') {
            Some((p, l)) => (p.to_string(), l.to_string()),
            None => (String::new(), qname.clone()),
        };
        let ns = scopes
            .iter()
            .rev()
            .find_map(|s| s.get(&prefix))
            .cloned()
            .unwrap_or_default();
        let mut el = Element {
            local,
            ns,
            children: Vec::new(),
            text: String::new(),
        };
        if !self_closing {
            loop {
                let r = self.rest();
                if r.is_empty() {
                    return Err("unexpected end".into());
                }
                if r.starts_with("</") {
                    let end = r.find('>').ok_or("unterminated end tag")?;
                    let close = r[2..end].trim();
                    if close != qname {
                        return Err("mismatched end tag".into());
                    }
                    self.pos += end + 1;
                    break;
                } else if r.starts_with("<!--") {
                    let end = r.find("-->").ok_or("unterminated comment")?;
                    self.pos += end + 3;
                } else if r.starts_with("<![CDATA[") {
                    let end = r.find("]]>").ok_or("unterminated cdata")?;
                    el.text.push_str(&r[9..end]);
                    self.pos += end + 3;
                } else if r.starts_with("<?") {
                    let end = r.find("?>").ok_or("unterminated pi")?;
                    self.pos += end + 2;
                } else if r.starts_with('<') {
                    let child = self.element(scopes)?;
                    el.children.push(child);
                } else {
                    let end = r.find('<').unwrap_or(r.len());
                    el.text.push_str(&decode_entities(&r[..end])?);
                    self.pos += end;
                }
            }
        }
        scopes.pop();
        Ok(el)
    }
}

pub(crate) fn parse(xml: &str) -> Result<Element, String> {
    let text = xml.trim_start_matches('\u{feff}');
    let mut p = Parser { s: text, pos: 0 };
    p.skip_misc()?;
    let mut scopes = Vec::new();
    let root = p.element(&mut scopes)?;
    p.skip_misc()?;
    if !p.rest().trim().is_empty() {
        return Err("content after root".into());
    }
    Ok(root)
}

impl Element {
    pub(crate) fn inner_text(&self) -> String {
        let mut t = self.text.clone();
        for c in &self.children {
            t.push_str(&c.inner_text());
        }
        t
    }
}
