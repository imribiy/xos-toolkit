#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Tone {
    #[default]
    Neutral,
    Green,
    Red,
    Orange,
    Blue,
    Muted,
}

impl Tone {
    pub fn code(self) -> i32 {
        match self {
            Tone::Neutral => 0,
            Tone::Green => 1,
            Tone::Red => 2,
            Tone::Orange => 3,
            Tone::Blue => 4,
            Tone::Muted => 5,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BtnStyle {
    #[default]
    Action,
    Enable,
    Disable,
    Warning,
    Link,
}

impl BtnStyle {
    pub fn code(self) -> i32 {
        match self {
            BtnStyle::Action => 0,
            BtnStyle::Enable => 1,
            BtnStyle::Disable => 2,
            BtnStyle::Warning => 3,
            BtnStyle::Link => 4,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Kind {
    #[default]
    Button,
    Combo,
    Check,
    TextInput,
    Label,
    Muted,
    Heading,
    Stat,
    Table,
    Progress,
    Spacer,
    Mono,
    Chip,
}

impl Kind {
    pub fn code(self) -> i32 {
        match self {
            Kind::Button => 0,
            Kind::Combo => 1,
            Kind::Check => 2,
            Kind::TextInput => 3,
            Kind::Label => 4,
            Kind::Muted => 5,
            Kind::Heading => 6,
            Kind::Stat => 7,
            Kind::Table => 8,
            Kind::Progress => 9,
            Kind::Spacer => 10,
            Kind::Mono => 11,
            Kind::Chip => 12,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Column {
    pub title: String,
    pub width: f32,
}

impl Column {
    pub fn new(title: impl Into<String>, width: f32) -> Self {
        Self { title: title.into(), width }
    }
    pub fn stretch(title: impl Into<String>) -> Self {
        Self { title: title.into(), width: 0.0 }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RowButton {
    pub id: String,
    pub text: String,
    pub style: BtnStyle,
    pub enabled: bool,
}

impl RowButton {
    pub fn new(id: impl Into<String>, text: impl Into<String>, style: BtnStyle) -> Self {
        Self { id: id.into(), text: text.into(), style, enabled: true }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TableRow {
    pub id: String,
    pub cells: Vec<String>,
    pub checked: bool,
    pub tone: Tone,
    pub enabled: bool,
    pub selected: bool,
    pub tooltip: String,
    pub buttons: Vec<RowButton>,
}

impl Default for TableRow {
    fn default() -> Self {
        Self {
            id: String::new(),
            cells: Vec::new(),
            checked: false,
            tone: Tone::Neutral,
            enabled: true,
            selected: false,
            tooltip: String::new(),
            buttons: Vec::new(),
        }
    }
}

impl TableRow {
    pub fn new(id: impl Into<String>, cells: Vec<String>) -> Self {
        Self { id: id.into(), cells, ..Default::default() }
    }
    pub fn checked(mut self, v: bool) -> Self {
        self.checked = v;
        self
    }
    pub fn tone(mut self, t: Tone) -> Self {
        self.tone = t;
        self
    }
    pub fn enabled(mut self, v: bool) -> Self {
        self.enabled = v;
        self
    }
    pub fn selected(mut self, v: bool) -> Self {
        self.selected = v;
        self
    }
    pub fn tooltip(mut self, t: impl Into<String>) -> Self {
        self.tooltip = t.into();
        self
    }
    pub fn button(mut self, b: RowButton) -> Self {
        self.buttons.push(b);
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<TableRow>,
    pub checkable: bool,
    pub selectable: bool,
    pub sortable: bool,
    pub height: f32,
    pub empty_text: String,
}

impl Table {
    pub fn new(columns: Vec<Column>, rows: Vec<TableRow>) -> Self {
        Self { columns, rows, height: 320.0, ..Default::default() }
    }
    pub fn checkable(mut self, v: bool) -> Self {
        self.checkable = v;
        self
    }
    pub fn selectable(mut self, v: bool) -> Self {
        self.selectable = v;
        self
    }
    pub fn sortable(mut self, v: bool) -> Self {
        self.sortable = v;
        self
    }
    pub fn height(mut self, h: f32) -> Self {
        self.height = h;
        self
    }
    pub fn empty_text(mut self, t: impl Into<String>) -> Self {
        self.empty_text = t.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Control {
    pub id: String,
    pub kind: Kind,
    pub text: String,
    pub style: BtnStyle,
    pub tone: Tone,
    pub enabled: bool,
    pub always_enabled: bool,
    pub options: Vec<String>,
    pub selected: i32,
    pub checked: bool,
    pub value: String,
    pub placeholder: String,
    pub tooltip: String,
    pub width: f32,
    pub max_len: i32,
    pub progress: f32,
    pub table: Option<Table>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: Kind::Label,
            text: String::new(),
            style: BtnStyle::Action,
            tone: Tone::Neutral,
            enabled: true,
            always_enabled: false,
            options: Vec::new(),
            selected: -1,
            checked: false,
            value: String::new(),
            placeholder: String::new(),
            tooltip: String::new(),
            width: 0.0,
            max_len: 0,
            progress: 0.0,
            table: None,
        }
    }
}

impl Control {
    pub fn button(id: impl Into<String>, text: impl Into<String>, style: BtnStyle) -> Self {
        Self { id: id.into(), kind: Kind::Button, text: text.into(), style, ..Default::default() }
    }
    pub fn enable(id: impl Into<String>) -> Self {
        Self::button(id, "Enable", BtnStyle::Enable)
    }
    pub fn disable(id: impl Into<String>) -> Self {
        Self::button(id, "Disable", BtnStyle::Disable)
    }
    pub fn combo(id: impl Into<String>, options: Vec<String>, selected: i32) -> Self {
        Self { id: id.into(), kind: Kind::Combo, options, selected, width: 180.0, ..Default::default() }
    }
    pub fn check(id: impl Into<String>, text: impl Into<String>, checked: bool) -> Self {
        Self { id: id.into(), kind: Kind::Check, text: text.into(), checked, ..Default::default() }
    }
    pub fn text_input(id: impl Into<String>, value: impl Into<String>, placeholder: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: Kind::TextInput,
            value: value.into(),
            placeholder: placeholder.into(),
            ..Default::default()
        }
    }
    pub fn label(text: impl Into<String>) -> Self {
        Self { kind: Kind::Label, text: text.into(), ..Default::default() }
    }
    pub fn muted(text: impl Into<String>) -> Self {
        Self { kind: Kind::Muted, text: text.into(), ..Default::default() }
    }
    pub fn heading(text: impl Into<String>) -> Self {
        Self { kind: Kind::Heading, text: text.into(), ..Default::default() }
    }
    pub fn mono(text: impl Into<String>) -> Self {
        Self { kind: Kind::Mono, text: text.into(), ..Default::default() }
    }
    pub fn stat(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self { kind: Kind::Stat, text: label.into(), value: value.into(), ..Default::default() }
    }
    pub fn chip(text: impl Into<String>, tone: Tone) -> Self {
        Self { kind: Kind::Chip, text: text.into(), tone, ..Default::default() }
    }
    pub fn table(id: impl Into<String>, table: Table) -> Self {
        Self { id: id.into(), kind: Kind::Table, table: Some(table), ..Default::default() }
    }
    pub fn progress(id: impl Into<String>, fraction: f32, text: impl Into<String>) -> Self {
        Self { id: id.into(), kind: Kind::Progress, progress: fraction, text: text.into(), ..Default::default() }
    }
    pub fn spacer() -> Self {
        Self { kind: Kind::Spacer, ..Default::default() }
    }
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }
    pub fn enabled(mut self, v: bool) -> Self {
        self.enabled = v;
        self
    }
    pub fn disabled(self) -> Self {
        self.enabled(false)
    }
    pub fn always_enabled(mut self) -> Self {
        self.always_enabled = true;
        self
    }
    pub fn tooltip(mut self, t: impl Into<String>) -> Self {
        self.tooltip = t.into();
        self
    }
    pub fn width(mut self, w: f32) -> Self {
        self.width = w;
        self
    }
    pub fn tone(mut self, t: Tone) -> Self {
        self.tone = t;
        self
    }
    pub fn max_len(mut self, n: i32) -> Self {
        self.max_len = n;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    pub controls: Vec<Control>,
    pub bottom: bool,
}

impl Row {
    pub fn new(controls: Vec<Control>) -> Self {
        Self { controls, bottom: false }
    }
    pub fn actions(controls: Vec<Control>) -> Self {
        Self { controls, bottom: true }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Badge {
    pub text: String,
    pub tone: Tone,
    pub tooltip: String,
}

impl Badge {
    pub fn new(text: impl Into<String>, tone: Tone) -> Self {
        Self { text: text.into(), tone, tooltip: String::new() }
    }
    pub fn tooltip(mut self, t: impl Into<String>) -> Self {
        self.tooltip = t.into();
        self
    }
    pub fn checking() -> Self {
        Self::new("Checking", Tone::Neutral)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub id: String,
    pub title: String,
    pub description: String,
    pub badge: Option<Badge>,
    pub full_width: bool,
    pub visible: bool,
    pub searchable: bool,
    pub rows: Vec<Row>,
}

impl Card {
    pub fn new(id: impl Into<String>, title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            badge: None,
            full_width: false,
            visible: true,
            searchable: true,
            rows: Vec::new(),
        }
    }
    pub fn badge(mut self, b: Badge) -> Self {
        self.badge = Some(b);
        self
    }
    pub fn badge_opt(mut self, b: Option<Badge>) -> Self {
        self.badge = b;
        self
    }
    pub fn full_width(mut self) -> Self {
        self.full_width = true;
        self
    }
    pub fn visible(mut self, v: bool) -> Self {
        self.visible = v;
        self
    }
    pub fn not_searchable(mut self) -> Self {
        self.searchable = false;
        self
    }
    pub fn row(mut self, r: Row) -> Self {
        self.rows.push(r);
        self
    }
    pub fn controls(self, c: Vec<Control>) -> Self {
        self.row(Row::new(c))
    }
    pub fn actions(self, c: Vec<Control>) -> Self {
        self.row(Row::actions(c))
    }
    pub fn enable_disable(self, prefix: &str) -> Self {
        self.actions(vec![
            Control::enable(format!("{prefix}.enable")),
            Control::disable(format!("{prefix}.disable")),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PageModel {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub cards: Vec<Card>,
    pub max_width: f32,
    pub two_column: bool,
    pub overlay: Option<String>,
}

impl PageModel {
    pub fn new(id: impl Into<String>, title: impl Into<String>, subtitle: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            subtitle: subtitle.into(),
            cards: Vec::new(),
            max_width: 1080.0,
            two_column: true,
            overlay: None,
        }
    }
    pub fn single_column(mut self) -> Self {
        self.two_column = false;
        self
    }
    pub fn max_width(mut self, w: f32) -> Self {
        self.max_width = w;
        self
    }
    pub fn card(mut self, c: Card) -> Self {
        self.cards.push(c);
        self
    }
    pub fn overlay(mut self, text: Option<String>) -> Self {
        self.overlay = text;
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventKind {
    Click,
    Select(i32),
    Check(bool),
    Text(String),
    Submit(String),
    RowCheck { row: usize, checked: bool },
    RowButton { row: usize, button: String },
    RowSelect(usize),
    RowActivate(usize),
    HeaderClick(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub card: String,
    pub control: String,
    pub kind: EventKind,
}

impl Event {
    pub fn is_click(&self, control: &str) -> bool {
        self.control == control && self.kind == EventKind::Click
    }
}
