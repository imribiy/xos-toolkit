use crate::{BadgeD, CardD, CellRowD, ColumnD, ControlD, PairD, RowButtonD, RowD};
use slint::{Model, ModelRc, SharedString, VecModel};
use std::rc::Rc;
use xos_core::ui as m;

fn ss(s: &str) -> SharedString {
    SharedString::from(s)
}

fn glyphs(s: &str) -> SharedString {
    if !s.chars().any(|c| matches!(c, '\u{21BB}' | '\u{2715}' | '\u{27F3}' | '\u{2716}')) {
        return ss(s);
    }
    let out = s
        .replace("\u{21BB}  ", "")
        .replace("\u{27F3}  ", "")
        .replace(['\u{21BB}', '\u{27F3}'], "")
        .replace(['\u{2715}', '\u{2716}'], "\u{00D7}");
    SharedString::from(out.as_str())
}

fn sync_model<T: Clone + PartialEq + 'static>(model: &VecModel<T>, items: Vec<T>) {
    let n = items.len();
    for (i, item) in items.into_iter().enumerate() {
        if i < model.row_count() {
            if model.row_data(i).as_ref() != Some(&item) {
                model.set_row_data(i, item);
            }
        } else {
            model.push(item);
        }
    }
    while model.row_count() > n {
        model.remove(model.row_count() - 1);
    }
}

fn is_stretchy(c: &m::Control) -> bool {
    use m::Kind::*;
    match c.kind {
        Label | Muted | Stat | Table | Progress | Spacer | Mono => true,
        TextInput => c.width <= 0.0,
        _ => false,
    }
}

#[derive(Default)]
struct CtlCache {
    src: Option<m::Control>,
    value: ControlD,
    options_src: Vec<String>,
    options: Rc<VecModel<SharedString>>,
    columns_src: Vec<m::Column>,
    columns: Rc<VecModel<ColumnD>>,
    rows_src: Vec<m::TableRow>,
    rows: Rc<VecModel<CellRowD>>,
}

fn a11y_label(text: &str, id: &str) -> String {
    if text.chars().any(char::is_alphanumeric) {
        return String::new();
    }
    let words = id.replace(['_', '-', '.'], " ");
    let mut c = words.trim().chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod a11y_tests {
    use super::a11y_label;

    #[test]
    fn glyph_only_buttons_get_a_spoken_name() {
        assert_eq!(a11y_label("×", "delete"), "Delete");
        assert_eq!(a11y_label("↻", "open_folder"), "Open folder");
        assert_eq!(a11y_label("Remove", "remove"), "");
        assert_eq!(a11y_label("×", ""), "");
    }
}

fn cell_row(r: &m::TableRow) -> CellRowD {
    CellRowD {
        id: ss(&r.id),
        label: ss(&r.cells.iter().filter(|c| !c.trim().is_empty()).cloned().collect::<Vec<_>>().join(" | ")),
        cells: ModelRc::new(VecModel::from(r.cells.iter().map(|c| ss(c)).collect::<Vec<_>>())),
        checked: r.checked,
        tone: r.tone.code(),
        enabled: r.enabled,
        selected: r.selected,
        tooltip: ss(&r.tooltip),
        buttons: ModelRc::new(VecModel::from(
            r.buttons
                .iter()
                .map(|b| RowButtonD {
                    id: ss(&b.id),
                    text: glyphs(&b.text),
                    label: ss(&a11y_label(&b.text, &b.id)),
                    style: b.style.code(),
                    enabled: b.enabled,
                })
                .collect::<Vec<_>>(),
        )),
    }
}

impl CtlCache {
    fn update(&mut self, c: &m::Control) -> ControlD {
        if self.src.as_ref() == Some(c) {
            return self.value.clone();
        }
        if self.options_src != c.options {
            sync_model(&self.options, c.options.iter().map(|s| ss(s)).collect());
            self.options_src = c.options.clone();
        }
        let empty = m::Table::default();
        let t = c.table.as_ref().unwrap_or(&empty);
        if self.columns_src != t.columns {
            sync_model(&self.columns, t.columns.iter().map(|col| ColumnD { title: ss(&col.title), width: col.width }).collect());
            self.columns_src = t.columns.clone();
        }
        let n = t.rows.len();
        for (i, r) in t.rows.iter().enumerate() {
            if i < self.rows_src.len() {
                if &self.rows_src[i] != r {
                    self.rows.set_row_data(i, cell_row(r));
                }
            } else {
                self.rows.push(cell_row(r));
            }
        }
        while self.rows.row_count() > n {
            self.rows.remove(self.rows.row_count() - 1);
        }
        self.rows_src = t.rows.clone();
        self.value = ControlD {
            id: ss(&c.id),
            kind: c.kind.code(),
            text: glyphs(&c.text),
            style: c.style.code(),
            tone: c.tone.code(),
            enabled: c.enabled,
            options: ModelRc::from(self.options.clone()),
            selected: c.selected,
            checked: c.checked,
            value: ss(&c.value),
            placeholder: ss(&c.placeholder),
            tooltip: ss(&c.tooltip),
            width: c.width,
            max_len: c.max_len,
            progress: c.progress,
            columns: ModelRc::from(self.columns.clone()),
            rows: ModelRc::from(self.rows.clone()),
            checkable: t.checkable,
            selectable: t.selectable,
            sortable: t.sortable,
            table_height: t.height,
            empty_text: ss(&t.empty_text),
            has_buttons: t.rows.iter().any(|r| !r.buttons.is_empty()),
            buttons_width: t
                .rows
                .iter()
                .map(|r| {
                    r.buttons
                        .iter()
                        .map(|b| b.text.chars().count() as f32 * 7.0 + if b.style == m::BtnStyle::Link { 10.0 } else { 34.0 } + 6.0)
                        .sum::<f32>()
                })
                .fold(0.0, f32::max),
        };
        self.src = Some(c.clone());
        self.value.clone()
    }
}

#[derive(Default)]
struct RowCache {
    src: Option<m::Row>,
    value: RowD,
    controls: Rc<VecModel<ControlD>>,
    caches: Vec<CtlCache>,
}

impl RowCache {
    fn update(&mut self, r: &m::Row) -> RowD {
        if self.src.as_ref() == Some(r) {
            return self.value.clone();
        }
        let mut out = Vec::with_capacity(r.controls.len());
        for (i, c) in r.controls.iter().enumerate() {
            if i >= self.caches.len() {
                self.caches.push(CtlCache::default());
            }
            out.push(self.caches[i].update(c));
        }
        self.caches.truncate(r.controls.len());
        sync_model(&self.controls, out);
        self.value = RowD {
            controls: ModelRc::from(self.controls.clone()),
            bottom: r.bottom,
            filler: !r.controls.iter().any(is_stretchy),
        };
        self.src = Some(r.clone());
        self.value.clone()
    }
}

#[derive(Default)]
struct CardCache {
    src: Option<(m::Card, bool)>,
    value: CardD,
    rows: Rc<VecModel<RowD>>,
    caches: Vec<RowCache>,
}

impl CardCache {
    fn update(&mut self, c: &m::Card, highlight: bool) -> CardD {
        if let Some((sc, sh)) = &self.src {
            if sc == c && *sh == highlight {
                return self.value.clone();
            }
        }
        let mut out = Vec::with_capacity(c.rows.len());
        for (i, r) in c.rows.iter().enumerate() {
            if i >= self.caches.len() {
                self.caches.push(RowCache::default());
            }
            out.push(self.caches[i].update(r));
        }
        self.caches.truncate(c.rows.len());
        sync_model(&self.rows, out);
        let badge = c.badge.clone().unwrap_or_default();
        self.value = CardD {
            id: ss(&c.id),
            title: ss(&c.title),
            description: ss(&c.description),
            has_badge: c.badge.is_some(),
            badge: BadgeD { text: ss(&badge.text), tone: badge.tone.code(), tooltip: ss(&badge.tooltip) },
            rows: ModelRc::from(self.rows.clone()),
            highlight,
        };
        self.src = Some((c.clone(), highlight));
        self.value.clone()
    }
}

#[derive(Default)]
struct PairCache {
    a: CardCache,
    b: CardCache,
}

pub struct PageView {
    pub pairs: Rc<VecModel<PairD>>,
    caches: Vec<PairCache>,
}

impl PageView {
    pub fn new() -> Self {
        Self { pairs: Rc::new(VecModel::default()), caches: Vec::new() }
    }

    pub fn model(&self) -> ModelRc<PairD> {
        ModelRc::from(self.pairs.clone())
    }

    pub fn update(&mut self, pairs: Vec<(m::Card, Option<m::Card>)>, highlight: &str) {
        let n = pairs.len();
        let mut out = Vec::with_capacity(n);
        for (i, (a, b)) in pairs.iter().enumerate() {
            if i >= self.caches.len() {
                self.caches.push(PairCache::default());
            }
            let pc = &mut self.caches[i];
            let ad = pc.a.update(a, !highlight.is_empty() && a.id == highlight);
            let bd = match b {
                Some(b) => pc.b.update(b, !highlight.is_empty() && b.id == highlight),
                None => CardD::default(),
            };
            out.push(PairD { a: ad, b: bd, two: b.is_some() });
        }
        self.caches.truncate(n);
        sync_model(&self.pairs, out);
    }
}

pub fn pair_cards(cards: &[m::Card], two_column: bool) -> Vec<(m::Card, Option<m::Card>)> {
    let visible: Vec<&m::Card> = cards.iter().filter(|c| c.visible).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < visible.len() {
        let a = visible[i];
        if !two_column || a.full_width {
            out.push((a.clone(), None));
            i += 1;
            continue;
        }
        if i + 1 < visible.len() && !visible[i + 1].full_width {
            out.push((a.clone(), Some(visible[i + 1].clone())));
            i += 2;
        } else {
            out.push((a.clone(), None));
            i += 1;
        }
    }
    out
}

pub fn apply_busy(model: &mut m::PageModel) {
    for card in &mut model.cards {
        for row in &mut card.rows {
            for c in &mut row.controls {
                if !c.always_enabled && matches!(c.kind, m::Kind::Button | m::Kind::Combo | m::Kind::Check | m::Kind::Table) {
                    c.enabled = false;
                }
            }
        }
    }
}
