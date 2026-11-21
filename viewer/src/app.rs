//! Thin egui presentation layer.
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::net::ViewerSession;
use crate::net::{Output, SharedOutput, State};
use eframe::egui;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    View,
    Share,
}

pub struct App {
    page: Page,
    nearby: crate::ui::NearbyModel,
    routes: Vec<trinix_discovery::Device>,
    browse: Option<std::sync::mpsc::Receiver<Vec<trinix_discovery::Device>>>,
    last_browse: std::time::Instant,
    pair_flow: crate::ui::PairFlow,
    pair_events: Option<std::sync::mpsc::Receiver<crate::devices::PairEvent>>,
    pair_decision: Option<tokio::sync::oneshot::Sender<bool>>,
    pair_target: Option<std::net::SocketAddr>,
    forget_pending: Option<String>,
    device_name: String,
    themed: bool,
    fullscreen: bool,
    address: String,
    share_address: String,
    share_fps: u32,
    share_bitrate: u32,
    allow_legacy: bool,
    allow_control: bool,
    extend: bool,
    commands: Option<tokio::sync::mpsc::Sender<crate::net::Command>>,
    input_focused: bool,
    input_modifiers: egui::Modifiers,
    host: Option<crate::host::HostProcess>,
    host_message: String,
    share_qr: Option<(String, qrcode::QrCode)>,
    host_error: bool,
    last_host_poll: std::time::Instant,
    output: SharedOutput,
    texture: Option<egui::TextureHandle>,
    task: Option<tokio::task::JoinHandle<()>>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    runtime: tokio::runtime::Runtime,
}
impl App {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            page: Page::View,
            nearby: crate::ui::NearbyModel::default(),
            routes: Vec::new(),
            browse: None,
            last_browse: std::time::Instant::now() - std::time::Duration::from_secs(10),
            pair_flow: crate::ui::PairFlow::Idle,
            pair_events: None,
            pair_decision: None,
            pair_target: None,
            forget_pending: None,
            device_name: trinix_security::store::config_dir()
                .and_then(|directory| trinix_security::pairing::DeviceIdentity::open(&directory))
                .map_or_else(
                    |_| "Device".into(),
                    |identity| identity.friendly_name().into(),
                ),
            themed: false,
            fullscreen: false,
            address: String::new(),
            share_address: local_endpoint(),
            share_fps: 30,
            share_bitrate: 4000,
            allow_legacy: false,
            allow_control: false,
            extend: false,
            commands: None,
            input_focused: false,
            input_modifiers: egui::Modifiers::NONE,
            host: None,
            host_message: String::new(),
            share_qr: None,
            host_error: false,
            last_host_poll: std::time::Instant::now(),
            output: Arc::new(Mutex::new(Output {
                state: State::Closed,
                ..Default::default()
            })),
            texture: None,
            task: None,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        })
    }
    fn disconnect(&mut self) {
        self.commands = None;
        self.input_focused = false;
        self.input_modifiers = egui::Modifiers::NONE;
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.texture = None;
        self.output = Arc::new(Mutex::new(Output {
            state: State::Closed,
            ..Default::default()
        }));
    }
    fn command(&mut self, action: crate::net::ControlAction) {
        let command = crate::net::Command {
            generation: self
                .output
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .control_epoch,
            action,
        };
        if self
            .commands
            .as_ref()
            .is_some_and(|sender| sender.try_send(command).is_err())
        {
            self.disconnect();
        }
    }
    fn connect_paired(&mut self, address: std::net::SocketAddr, fingerprint: [u8; 32]) {
        self.disconnect();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if let (Ok(directory), Ok(decoder)) = (
            trinix_security::store::config_dir(),
            codec_gst::decoder::Decoder::new(),
        ) {
            let session = ViewerSession::new(decoder);
            self.output = session.output.clone();
            self.commands = Some(session.commands.clone());
            self.task = Some(self.runtime.spawn(session.run_paired(
                address,
                directory,
                fingerprint,
            )));
        }
    }
    fn pair_device(
        &mut self,
        address: std::net::SocketAddr,
        offer: Option<trinix_security::pairing::PairingOffer>,
    ) {
        if self.pair_events.is_some() {
            return;
        }
        let Ok(directory) = trinix_security::store::config_dir() else {
            self.pair_flow = crate::ui::PairFlow::Failed;
            return;
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        self.pair_events = Some(rx);
        self.pair_target = Some(address);
        self.pair_flow = crate::ui::PairFlow::Idle;
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        self.runtime
            .spawn(crate::devices::pair(address, directory, offer, tx));
    }
    fn devices_ui(&mut self, ui: &mut egui::Ui) {
        self.pair_prompt(ui);
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("Nearby devices")
                    .strong()
                    .size(16.0)
                    .color(TEXT),
            );
            if self.nearby.searching {
                hint(ui, "Looking for devices…");
            } else if self.nearby.rows.is_empty() {
                hint(ui, "No devices found nearby.");
            }
            let mut selected = None;
            for (index, row) in self.nearby.rows.iter().enumerate() {
                let clicked = ui
                    .add_enabled_ui(self.pair_events.is_none(), |ui| {
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::Button::new(egui::RichText::new(&row.name).color(TEXT))
                                .shortcut_text(
                                    egui::RichText::new(if row.paired { "Paired" } else { "New" })
                                        .color(SECONDARY),
                                )
                                .min_size(egui::vec2(ui.available_width(), 40.0)),
                        )
                    })
                    .inner
                    .clicked();
                if clicked {
                    selected = Some(index);
                }
            }
            if let Some(device) = selected.and_then(|index| self.routes.get(index)).cloned() {
                if let Some(address) = device.addresses.first().copied() {
                    let selected = trinix_security::store::config_dir().and_then(|directory| {
                        let store = trinix_security::store::DeviceStore::open(&directory)?;
                        if store
                            .peers()
                            .iter()
                            .any(|peer| peer.id() == device.metadata.id())
                        {
                            store.find(device.metadata.id()).map(Some)
                        } else {
                            Ok(None)
                        }
                    });
                    match selected {
                        Ok(Some(peer)) => self.connect_paired(address, peer.fingerprint),
                        Ok(None) => self.pair_device(address, None),
                        Err(_) => {
                            self.pair_flow = crate::ui::PairFlow::Failed;
                        }
                    }
                }
            }
            if ui
                .add_sized(
                    [ui.available_width(), 36.0],
                    egui::Button::new("Search again"),
                )
                .clicked()
                && self.browse.is_none()
            {
                self.nearby.searching = true;
                self.browse = crate::devices::browse().ok();
                self.last_browse = std::time::Instant::now();
            }
        });
        hint(ui, "Nearby may not work on guest or shared Wi-Fi");
    }

    fn paired_section(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Paired devices", |ui| {
            if let Ok(directory) = trinix_security::store::config_dir() {
                if let Ok(mut store) = trinix_security::store::DeviceStore::open(&directory) {
                    for device in store.list() {
                        let pending = self.forget_pending.as_ref() == Some(&device.device_id);
                        let name = trinix_security::pairing::sanitize_name(&device.friendly_name);
                        match forget_choice(ui, &name, pending) {
                            Some(ForgetChoice::Forget) => {
                                self.forget_pending = Some(device.device_id.clone());
                            }
                            Some(ForgetChoice::Confirm) => {
                                if let Some(host) = &mut self.host {
                                    let _ =
                                        host.command(trinix_security::managed::Command::Forget(
                                            device.device_id.clone(),
                                        ));
                                } else {
                                    let _ = store.unpair(&device.device_id);
                                }
                                self.forget_pending = None;
                            }
                            Some(ForgetChoice::Cancel) => self.forget_pending = None,
                            None => {}
                        }
                    }
                }
                ui.add_space(6.0);
                hint(ui, "This device");
                let save_width = 108.0;
                ui.horizontal(|ui| {
                    let field_width =
                        (ui.available_width() - save_width - ui.spacing().item_spacing.x).max(48.0);
                    ui.add_sized(
                        [field_width, 36.0],
                        egui::TextEdit::singleline(&mut self.device_name).char_limit(32),
                    );
                    if ui
                        .add_sized([save_width, 36.0], egui::Button::new("Save name"))
                        .clicked()
                    {
                        if let Ok(mut identity) =
                            trinix_security::pairing::DeviceIdentity::open(&directory)
                        {
                            let _ = identity.set_friendly_name(&self.device_name);
                            self.device_name = identity.friendly_name().into();
                        }
                    }
                });
            }
        });
    }
    fn pair_prompt(&mut self, ui: &mut egui::Ui) {
        let prompt = match &self.pair_flow {
            crate::ui::PairFlow::Check(code) => Some((code.clone(), false)),
            crate::ui::PairFlow::Waiting(code) => Some((code.clone(), true)),
            crate::ui::PairFlow::Failed => {
                ui.colored_label(
                    DANGER,
                    "Pairing did not finish. Start again on both devices.",
                );
                None
            }
            crate::ui::PairFlow::Paired => {
                ui.label(
                    egui::RichText::new(
                        "Paired. Next time, pick it from the list. No code needed.",
                    )
                    .color(ACTION),
                );
                None
            }
            crate::ui::PairFlow::Idle => None,
        };
        let Some((code, waiting)) = prompt else {
            return;
        };
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("Check the code")
                    .strong()
                    .size(16.0)
                    .color(TEXT),
            );
            hint(ui, "Check that both devices show the same code.");
            code_line(ui, &code);
            if waiting {
                hint(
                    ui,
                    "Waiting for the other device… They need to press Yes too.",
                );
                return;
            }
            let mut choice = None;
            if action_button(ui, "Yes, codes match").clicked() {
                choice = Some(true);
            }
            if ui
                .add_sized([ui.available_width(), 40.0], egui::Button::new("No"))
                .clicked()
            {
                choice = Some(false);
            }
            if let Some(choice) = choice {
                self.pair_flow.confirm(choice);
                if let Some(decision) = self.pair_decision.take() {
                    let _ = decision.send(choice);
                }
            }
        });
    }
    fn connect(&mut self) {
        if let Ok(offer) = trinix_security::pairing::PairingOffer::parse(
            self.address.trim(),
            &trinix_security::pairing::SystemClock,
        ) {
            self.pair_device(offer.address(), Some(offer));
            return;
        }
        self.disconnect();
        if let Err(error) = trinix_security::Endpoint::parse(&self.address, self.allow_legacy) {
            self.output.lock().unwrap_or_else(|e| e.into_inner()).error = Some(error.to_string());
            return;
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        match codec_gst::decoder::Decoder::new() {
            Ok(decoder) => {
                let session = ViewerSession::new(decoder);
                self.output = session.output.clone();
                self.commands = Some(session.commands.clone());
                self.task = Some(self.runtime.spawn(session.run(self.address.clone())));
            }
            Err(e) => {
                let mut output = self.output.lock().unwrap_or_else(|p| p.into_inner());
                output.state = State::Closed;
                output.error = Some(e.to_string());
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let mut output = self.output.lock().unwrap_or_else(|p| p.into_inner());
            output.state = State::Closed;
            output.error =
                Some("Video decoding is currently supported on Linux and Windows.".into());
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.page == Page::View
            && self.browse.is_none()
            && self.last_browse.elapsed() >= std::time::Duration::from_secs(10)
        {
            self.nearby.searching = true;
            self.browse = crate::devices::browse().ok();
            self.last_browse = std::time::Instant::now();
        }
        if let Some(result) = self.browse.as_ref().and_then(|rx| rx.try_recv().ok()) {
            let paired = trinix_security::store::config_dir()
                .and_then(|directory| trinix_security::store::DeviceStore::open(&directory))
                .map(|store| store.list())
                .unwrap_or_default();
            self.nearby.replace(result.iter().map(|device| {
                (
                    device.metadata.name().into(),
                    paired
                        .iter()
                        .any(|peer| peer.device_id == device.metadata.id()),
                )
            }));
            self.routes = result;
            self.browse = None;
        }
        if let Some(event) = self.pair_events.as_ref().and_then(|rx| rx.try_recv().ok()) {
            match event {
                crate::devices::PairEvent::Code(code, decision) => {
                    if self.pair_flow.code(&code) {
                        self.pair_decision = Some(decision);
                    }
                }
                crate::devices::PairEvent::Done(result) => {
                    self.pair_events = None;
                    self.pair_decision = None;
                    self.pair_flow = if result.is_ok() {
                        crate::ui::PairFlow::Paired
                    } else {
                        crate::ui::PairFlow::Failed
                    };
                    if let (Ok(fingerprint), Some(address)) = (result, self.pair_target.take()) {
                        self.connect_paired(address, fingerprint);
                    }
                }
            }
        }
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            self.task = None;
        }
        if self.last_host_poll.elapsed() >= std::time::Duration::from_millis(500) {
            self.last_host_poll = std::time::Instant::now();
            if let Some(host) = &mut self.host {
                match host.exited() {
                    Ok(true) => {
                        self.host_message = format!(
                            "Sharing stopped. {}",
                            host.diagnostics().unwrap_or_default()
                        );
                        self.host_error = true;
                        self.host = None;
                    }
                    Err(error) => {
                        self.host_message = format!("Unable to check sharing: {error}");
                        self.host_error = true;
                        self.host = None;
                    }
                    Ok(false) => {
                        let diagnostics = host.diagnostics().unwrap_or_default();
                        self.host_message = if diagnostics.contains("trinix-host listening on") {
                            format!("Sharing on {}", self.share_address)
                        } else {
                            "Starting sharing…".into()
                        };
                    }
                }
            }
        }
        self.ensure_theme(ctx);
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) && self.fullscreen {
            self.fullscreen = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        }
        self.show_navigation(ctx);
        self.show_toolbar(ctx);
        if self.page != Page::View && self.input_focused {
            self.command(crate::net::ControlAction::Input(
                trinix_core::InputEvent::ReleaseAll,
            ));
            self.input_focused = false;
            self.input_modifiers = egui::Modifiers::NONE;
        }
        let mut out = self.output.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(p) = out.picture.take() {
            if let Some(rgb) = crate::render::rgb(&p) {
                let image = egui::ColorImage::from_rgb([p.width as usize, p.height as usize], &rgb);
                match &mut self.texture {
                    Some(t) => t.set(image, egui::TextureOptions::LINEAR),
                    None => {
                        self.texture =
                            Some(ctx.load_texture("video", image, egui::TextureOptions::LINEAR))
                    }
                }
                out.stats.present_ms = p.decoded.elapsed().as_secs_f64() * 1000.0;
                eprintln!("decode->present submission: {:.2} ms", out.stats.present_ms);
            }
        }
        let snapshot = ViewSnapshot {
            control_available: out.control_available,
            controlling: out.controlling,
            state: out.state.clone(),
            stats: out.stats.clone(),
            error: out.error.clone(),
        };
        drop(out);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(CANVAS)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                if self.page == Page::Share {
                    self.show_share(ui, ctx);
                } else {
                    self.show_view(ui, ctx, &snapshot);
                }
            });
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
}

struct ViewSnapshot {
    state: State,
    stats: crate::net::Stats,
    error: Option<String>,
    control_available: bool,
    controlling: bool,
}

impl App {
    fn ensure_theme(&mut self, ctx: &egui::Context) {
        if self.themed {
            return;
        }
        let mut style = (*ctx.style()).clone();
        let mut visuals = egui::Visuals::light();
        visuals.panel_fill = CANVAS;
        visuals.window_fill = SURFACE;
        visuals.extreme_bg_color = SURFACE;
        visuals.faint_bg_color = SOFT;
        visuals.code_bg_color = SOFT;
        visuals.selection.bg_fill = SELECTION;
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, ACTION);
        visuals.hyperlink_color = ACTION;
        visuals.warn_fg_color = DANGER;
        visuals.error_fg_color = DANGER;
        visuals.window_corner_radius = egui::CornerRadius::same(10);
        visuals.menu_corner_radius = egui::CornerRadius::same(8);
        visuals.window_stroke = egui::Stroke::new(1.0_f32, LINE);
        visuals.indent_has_left_vline = false;
        visuals.slider_trailing_fill = true;
        let radius = egui::CornerRadius::same(8);
        for widget in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widget.corner_radius = radius;
        }
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);
        visuals.widgets.inactive.weak_bg_fill = SOFT;
        visuals.widgets.inactive.bg_fill = SURFACE;
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);
        visuals.widgets.hovered.weak_bg_fill = SELECTION;
        visuals.widgets.hovered.bg_fill = SELECTION;
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACTION);
        visuals.widgets.active.weak_bg_fill = egui::Color32::from_rgb(190, 222, 204);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(190, 222, 204);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
        visuals.widgets.open.weak_bg_fill = SELECTION;
        visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 8.0);
        style.spacing.interact_size.y = 36.0;
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(22.0));
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, egui::FontId::proportional(13.0));
        ctx.set_style(style);
        self.themed = true;
    }

    fn show_navigation(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(212.0)
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 16)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label(
                    egui::RichText::new("Trinix")
                        .strong()
                        .size(20.0)
                        .color(TEXT),
                );
                ui.add_space(16.0);
                if nav_button(ui, self.page == Page::View, "View a screen").clicked() {
                    self.page = Page::View;
                }
                if nav_button(ui, self.page == Page::Share, "Share this screen").clicked() {
                    self.page = Page::Share;
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Extended displays are in development.")
                            .size(12.0)
                            .color(SECONDARY),
                    );
                    ui.label(
                        egui::RichText::new("Alpha · viewing and control")
                            .size(12.0)
                            .color(SECONDARY),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("About")
                            .size(12.0)
                            .strong()
                            .color(SECONDARY),
                    );
                });
            });
    }

    fn show_toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let sharing = self.host.is_some();
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                    ui.painter().circle_filled(
                        rect.center(),
                        4.5,
                        if sharing {
                            ACTION
                        } else {
                            egui::Color32::from_rgb(176, 186, 180)
                        },
                    );
                    ui.label(
                        egui::RichText::new(if sharing {
                            "Sharing is on"
                        } else {
                            "Sharing is off"
                        })
                        .color(if sharing { TEXT } else { SECONDARY }),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.host.is_some() && ui.button("Stop sharing").clicked() {
                            self.host = None;
                            self.share_qr = None;
                            self.host_message = "Sharing stopped".into();
                            self.host_error = false;
                        }
                        if self.texture.is_some()
                            && ui
                                .button(if self.fullscreen {
                                    "Exit full screen"
                                } else {
                                    "Full screen"
                                })
                                .clicked()
                        {
                            self.fullscreen = !self.fullscreen;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(
                                self.fullscreen,
                            ));
                        }
                    });
                });
            });
    }

    fn show_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, snapshot: &ViewSnapshot) {
        let height = ui.available_height();
        if ui.available_width() >= 700.0 {
            ui.scope(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(300.0, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("view-controls")
                                .show(ui, |ui| self.view_controls(ui));
                        },
                    );
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| self.view_stage(ui, ctx, snapshot),
                    );
                });
            });
        } else {
            // The screen area keeps a caption-sized band. Extra controls scroll.
            let stage_height = (height * 0.38).clamp(148.0, 280.0);
            let controls = (height - stage_height - 12.0).max(140.0);
            egui::ScrollArea::vertical()
                .id_salt("view-controls")
                .max_height(controls)
                .show(ui, |ui| self.view_controls(ui));
            ui.add_space(12.0);
            self.view_stage(ui, ctx, snapshot);
        }
    }

    fn view_controls(&mut self, ui: &mut egui::Ui) {
        self.view_devices(ui);
        ui.collapsing("Can't find your device? Use a link", |ui| {
            self.link_row(ui);
        });
        self.paired_section(ui);
        ui.collapsing("Technical details", |ui| {
            ui.checkbox(
                &mut self.allow_legacy,
                "Connect to an older alpha (unencrypted)",
            );
        });
    }

    fn view_devices(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("View a screen")
                .strong()
                .size(22.0)
                .color(TEXT),
        );
        ui.add_space(2.0);
        hint(ui, "Pick a device that is sharing its screen.");
        ui.add_space(8.0);
        self.devices_ui(ui);
    }

    fn link_row(&mut self, ui: &mut egui::Ui) {
        if ui.available_width() < 260.0 {
            ui.add_sized(
                [ui.available_width(), 36.0],
                egui::TextEdit::singleline(&mut self.address)
                    .hint_text("Paste a connection link")
                    .char_limit(1024),
            );
            self.link_button(ui, ui.available_width());
        } else {
            ui.horizontal(|ui| {
                let button_width = 124.0;
                let field_width =
                    (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(48.0);
                ui.add_sized(
                    [field_width, 36.0],
                    egui::TextEdit::singleline(&mut self.address)
                        .hint_text("Paste a connection link")
                        .char_limit(1024),
                );
                self.link_button(ui, button_width);
            });
        }
    }

    fn link_button(&mut self, ui: &mut egui::Ui, width: f32) {
        if self.task.is_some() {
            if ui
                .add_sized([width, 36.0], egui::Button::new("Disconnect"))
                .clicked()
            {
                self.disconnect();
            }
        } else if ui
            .add_enabled(
                !self.address.trim().is_empty(),
                egui::Button::new("Connect").min_size(egui::vec2(width, 36.0)),
            )
            .clicked()
        {
            self.address = self.address.trim().to_owned();
            self.connect();
        }
    }

    fn view_stage(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, snapshot: &ViewSnapshot) {
        let size = ui.available_size();
        ui.allocate_ui_with_layout(size, egui::Layout::top_down(egui::Align::Min), |ui| {
            let rect = ui.max_rect();
            ui.painter()
                .rect_filled(rect, egui::CornerRadius::same(12), SURFACE);
            ui.painter().rect_stroke(
                rect,
                egui::CornerRadius::same(12),
                egui::Stroke::new(1.0_f32, LINE),
                egui::StrokeKind::Inside,
            );
            let inner = rect.shrink(16.0);
            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(inner), |ui| {
                ui.set_clip_rect(inner);
                self.stage_header(ui, snapshot);
                ui.add_space(8.0);
                self.show_picture(ui, ctx, snapshot.controlling);
            });
        });
    }

    fn stage_header(&mut self, ui: &mut egui::Ui, snapshot: &ViewSnapshot) {
        ui.horizontal(|ui| {
            let (label, dot) = match snapshot.state {
                State::Connecting => ("Connecting…", SECONDARY),
                State::Connected => ("Connected", ACTION),
                State::Reconnecting => ("Reconnecting…", SECONDARY),
                State::Closed => ("Not connected", SECONDARY),
            };
            let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 4.0, dot);
            ui.label(
                egui::RichText::new(label).color(if snapshot.state == State::Connected {
                    TEXT
                } else {
                    SECONDARY
                }),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.task.is_some() && ui.button("Disconnect").clicked() {
                    self.disconnect();
                }
                if snapshot.state == State::Connected && snapshot.control_available {
                    let mut enabled = snapshot.controlling;
                    if ui.checkbox(&mut enabled, "Control").changed() {
                        self.command(crate::net::ControlAction::Control(enabled));
                    }
                }
            });
        });
        if snapshot.state == State::Connected {
            ui.collapsing("Details", |ui| {
                ui.label(format!(
                    "{:.0} fps · {} kbit/s · {} ms",
                    snapshot.stats.fps, snapshot.stats.kbps, snapshot.stats.rtt_ms
                ));
            });
        }
        if let Some(error) = &snapshot.error {
            ui.colored_label(
                DANGER,
                "Couldn't connect. Check that the other device is sharing.",
            );
            ui.collapsing("Technical details", |ui| {
                ui.label(error);
            });
        }
    }

    fn show_picture(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, controlling: bool) {
        let Some(texture) = self.texture.clone() else {
            show_empty(ui);
            return;
        };
        let size = texture.size_vec2();
        let available = ui.available_size();
        let scale = (available.x / size.x).min(available.y / size.y).max(0.01);
        let scaled = size * scale;
        ui.add_space(((available.y - scaled.y) * 0.5).max(0.0));
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - scaled.x) * 0.5).max(0.0));
            let response = ui.add(egui::Image::new(&texture).fit_to_exact_size(scaled).sense(
                if controlling {
                    egui::Sense::click_and_drag()
                } else {
                    egui::Sense::hover()
                },
            ));
            if controlling
                && (response.clicked()
                    || response.drag_started()
                    || (response.hovered() && ctx.input(|i| i.pointer.any_pressed())))
            {
                response.request_focus();
            }
            let focused = controlling && response.has_focus() && ctx.input(|i| i.focused);
            if focused {
                let (mut events, modifiers) = ctx.input(|i| (i.events.clone(), i.modifiers));
                if !response.hovered() {
                    events.retain(|event| !matches!(event, egui::Event::MouseWheel { .. }));
                }
                let events = crate::input::translate(
                    &events,
                    response.rect,
                    &mut self.input_modifiers,
                    modifiers,
                );
                for event in events {
                    self.command(crate::net::ControlAction::Input(event));
                }
            } else if self.input_focused {
                self.command(crate::net::ControlAction::Input(
                    trinix_core::InputEvent::ReleaseAll,
                ));
                self.input_modifiers = egui::Modifiers::NONE;
            }
            self.input_focused = focused;
        });
    }

    fn show_share(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let height = ui.available_height();
        let width = ui.available_width().min(560.0);
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.horizontal_top(|ui| {
                let slack = (ui.available_width() - width).max(0.0) * 0.5;
                ui.add_space(slack);
                ui.allocate_ui_with_layout(
                    egui::vec2(width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("share-form")
                            .show(ui, |ui| self.share_form(ui, ctx));
                    },
                );
            });
        });
    }

    fn share_form(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label(
            egui::RichText::new("Share this screen")
                .strong()
                .size(22.0)
                .color(TEXT),
        );
        ui.add_space(2.0);
        if self.host.is_some() && !self.host_error && self.host_message.starts_with("Sharing on") {
            hint(
                ui,
                "Waiting for another device. On the other device, open Trinix and press View a screen.",
            );
        } else if self.host.is_some() && !self.host_error {
            hint(ui, "Starting sharing…");
        } else if !self.host_error {
            hint(ui, "Start sharing, then connect from the other device.");
        }
        ui.add_space(8.0);
        let pairing = self.host.as_ref().map(|host| host.pairing());
        if let Some(pairing) = pairing {
            self.share_pairing(ui, pairing);
        }
        self.share_options(ui);
        if self.host_error {
            ui.colored_label(
                DANGER,
                "Sharing could not continue. Open sharing details below.",
            );
        }
        self.share_link(ui, ctx);
        ui.collapsing("Paired devices", |ui| {
            if let Ok(directory) = trinix_security::store::config_dir() {
                if let Ok(store) = trinix_security::store::DeviceStore::open(&directory) {
                    for device in store.list() {
                        let pending = self.forget_pending.as_ref() == Some(&device.device_id);
                        let name = trinix_security::pairing::sanitize_name(&device.friendly_name);
                        match forget_choice(ui, &name, pending) {
                            Some(ForgetChoice::Forget) => {
                                self.forget_pending = Some(device.device_id.clone());
                            }
                            Some(ForgetChoice::Confirm) => {
                                if let Some(host) = &mut self.host {
                                    let _ =
                                        host.command(trinix_security::managed::Command::Forget(
                                            device.device_id.clone(),
                                        ));
                                }
                                self.forget_pending = None;
                            }
                            Some(ForgetChoice::Cancel) => self.forget_pending = None,
                            None => {}
                        }
                    }
                }
            }
        });
        ui.collapsing("Technical details", |ui| {
            ui.add_enabled_ui(self.host.is_none(), |ui| {
                ui.label("Sharing address");
                ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut self.share_address),
                );
                ui.add(egui::Slider::new(&mut self.share_fps, 1..=60).text("Frames per second"));
                ui.add(
                    egui::Slider::new(&mut self.share_bitrate, 500..=20_000)
                        .text("Video quality (kbit/s)"),
                );
            });
        });
        if !self.host_message.is_empty() {
            ui.collapsing("Sharing details", |ui| {
                ui.label(&self.host_message);
            });
        }
    }

    fn share_pairing(&mut self, ui: &mut egui::Ui, pairing: crate::host::PairStatus) {
        use trinix_security::managed::{Command, Status};
        let Some(state) = pairing.state else {
            return;
        };
        card().show(ui, |ui| match state {
            Status::Open(seconds) => {
                ui.label(format!(
                    "Pairing is open for {}:{:02}",
                    seconds / 60,
                    seconds % 60
                ));
            }
            Status::Locked | Status::Expired => {
                ui.label(egui::RichText::new("Pairing is closed").color(TEXT));
                if ui
                    .add_sized([ui.available_width(), 36.0], egui::Button::new("Renew"))
                    .clicked()
                {
                    if let Some(host) = &mut self.host {
                        let _ = host.command(Command::Renew);
                    }
                }
            }
            Status::Code(code) => {
                ui.label(
                    egui::RichText::new("Another device wants to see this screen")
                        .strong()
                        .size(16.0)
                        .color(TEXT),
                );
                hint(
                    ui,
                    "Check that both devices show the same code. Allow only a device you know.",
                );
                code_line(ui, &code);
                if action_button(ui, "Allow · Yes, codes match").clicked() {
                    if let Some(host) = &mut self.host {
                        let _ = host.command(Command::Confirm);
                    }
                }
                if ui
                    .add_sized(
                        [ui.available_width(), 40.0],
                        egui::Button::new("Don't allow"),
                    )
                    .clicked()
                {
                    if let Some(host) = &mut self.host {
                        let _ = host.command(Command::Deny);
                    }
                }
            }
        });
    }

    fn share_options(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            let idle = self.host.is_none();
            ui.add_enabled_ui(idle, |ui| {
                ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.horizontal(|ui| {
                        let each =
                            ((ui.available_width() - ui.spacing().item_spacing.x) / 2.0).max(40.0);
                        if mode_choice(ui, each, !self.extend, true, "Mirror").clicked() {
                            self.extend = false;
                        }
                        let available = cfg!(target_os = "linux")
                            && (std::env::var_os("WAYLAND_DISPLAY").is_some()
                                || std::env::var("XDG_SESSION_TYPE")
                                    .is_ok_and(|value| value == "wayland"));
                        if mode_choice(ui, each, self.extend, available, "Extend")
                            .on_hover_text("Create an extra desktop display. Requires a Wayland desktop with virtual-monitor support.")
                            .clicked()
                            && available
                        {
                            self.extend = true;
                        }
                    });
                });
            });
            ui.add_enabled(
                idle,
                egui::Checkbox::new(&mut self.allow_control, "Allow remote control"),
            );
            if idle
                && action_button(
                    ui,
                    if self.extend {
                        "Share extra display"
                    } else {
                        "Share this screen"
                    },
                )
                .clicked()
            {
                match crate::host::HostProcess::start_with_options(
                    &self.share_address,
                    self.share_fps,
                    self.share_bitrate,
                    self.allow_control,
                    self.extend,
                ) {
                    Ok(host) => {
                        self.host = Some(host);
                        self.host_message = "Starting sharing…".into();
                        self.host_error = false;
                    }
                    Err(error) => {
                        self.host_message = error.to_string();
                        self.host_error = true;
                    }
                }
            }
        });
    }

    fn share_link(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("Connect another way")
                    .strong()
                    .size(16.0)
                    .color(TEXT),
            );
            let invitation = self.host.as_ref().and_then(|host| host.invitation());
            if ui
                .add_enabled(
                    invitation.is_some(),
                    egui::Button::new("Copy connection link")
                        .min_size(egui::vec2(ui.available_width(), 36.0)),
                )
                .clicked()
            {
                if let Some(invitation) = invitation {
                    ctx.copy_text(invitation.to_link());
                }
            }
            let link = self.host.as_ref().and_then(|host| host.pairing().offer);
            match link {
                Some(link) => {
                    if self
                        .share_qr
                        .as_ref()
                        .is_none_or(|(cached, _)| *cached != link)
                    {
                        self.share_qr = qrcode::QrCode::new(link.as_bytes())
                            .ok()
                            .map(|code| (link, code));
                    }
                }
                None => self.share_qr = None,
            }
            if let Some((_, code)) = &self.share_qr {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("QR code for pairing").color(TEXT));
                hint(ui, "In-app scanning is not available yet.");
                ui.add_space(8.0);
                paint_qr(ui, code);
            }
        });
    }
}

fn show_empty(ui: &mut egui::Ui) {
    let available = ui.available_height();
    // A short stage (narrow window) keeps the caption and drops the drawing.
    let draw = available >= 168.0;
    ui.vertical_centered(|ui| {
        if draw {
            let spare = (available - 180.0).max(0.0);
            ui.add_space((spare * 0.38).max(8.0));
            let (response, painter) =
                ui.allocate_painter(egui::vec2(180.0, 96.0), egui::Sense::hover());
            let origin = response.rect.min;
            for (x, y, w, h) in [(4.0, 4.0, 106.0, 66.0), (86.0, 30.0, 86.0, 54.0)] {
                let rect = egui::Rect::from_min_size(origin + egui::vec2(x, y), egui::vec2(w, h));
                painter.rect_filled(rect, 6.0, SURFACE);
                painter.rect_stroke(
                    rect,
                    6.0,
                    egui::Stroke::new(1.5_f32, SECONDARY),
                    egui::StrokeKind::Inside,
                );
                painter.line_segment(
                    [
                        rect.center_bottom(),
                        rect.center_bottom() + egui::vec2(0.0, 8.0),
                    ],
                    egui::Stroke::new(1.5_f32, SECONDARY),
                );
            }
            painter.circle_filled(origin + egui::vec2(105.0, 63.0), 9.0, ACTION);
            ui.add_space(16.0);
        } else {
            ui.add_space((available * 0.12).clamp(4.0, 16.0));
        }
        ui.add(
            egui::Label::new(
                egui::RichText::new("Your other screen will appear here")
                    .size(16.0)
                    .color(TEXT),
            )
            .halign(egui::Align::Center),
        );
        if available >= 72.0 {
            ui.add(
                egui::Label::new(
                    egui::RichText::new("Choose a nearby device, or paste a connection link.")
                        .size(13.0)
                        .color(SECONDARY),
                )
                .halign(egui::Align::Center),
            );
        }
    });
}

fn nav_button(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 40.0), egui::Sense::click());
    let fill = if selected {
        SELECTION
    } else if response.hovered() {
        SOFT
    } else {
        egui::Color32::TRANSPARENT
    };
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(8), fill);
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect,
                egui::CornerRadius::same(8),
                egui::Stroke::new(1.5_f32, ACTION),
                egui::StrokeKind::Inside,
            );
        }
        ui.painter().text(
            rect.left_center() + egui::vec2(12.0, 0.0),
            egui::Align2::LEFT_CENTER,
            label,
            egui::FontId::proportional(15.0),
            if selected { ACTION } else { TEXT },
        );
    }
    response
}

fn mode_choice(
    ui: &mut egui::Ui,
    width: f32,
    selected: bool,
    enabled: bool,
    label: &str,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 36.0), egui::Sense::click());
    let fill = if !enabled {
        SOFT
    } else if selected {
        SELECTION
    } else if response.hovered() {
        SOFT
    } else {
        SURFACE
    };
    let text = if !enabled {
        SECONDARY
    } else if selected {
        ACTION
    } else {
        TEXT
    };
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            egui::CornerRadius::same(8),
            fill,
            egui::Stroke::new(1.0_f32, if selected && enabled { ACTION } else { LINE }),
            egui::StrokeKind::Inside,
        );
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(15.0),
            text,
        );
    }
    response
}

fn action_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 42.0), egui::Sense::click());
    let fill = if !ui.is_enabled() {
        SOFT
    } else if response.hovered() {
        egui::Color32::from_rgb(31, 99, 66)
    } else {
        ACTION
    };
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(10), fill);
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect,
                egui::CornerRadius::same(10),
                egui::Stroke::new(2.0_f32, TEXT),
                egui::StrokeKind::Inside,
            );
        }
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(16.0),
            if ui.is_enabled() {
                egui::Color32::WHITE
            } else {
                SECONDARY
            },
        );
    }
    response
}

fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(egui::Stroke::new(1.0_f32, LINE))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .outer_margin(egui::Margin::symmetric(0, 4))
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(SECONDARY).size(13.0));
}

fn code_line(ui: &mut egui::Ui, code: &str) {
    let shown = if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    };
    ui.add_space(4.0);
    ui.vertical_centered(|ui| {
        ui.label(
            egui::RichText::new(shown)
                .monospace()
                .size(40.0)
                .color(TEXT),
        );
    });
    ui.add_space(4.0);
}

fn paint_qr(ui: &mut egui::Ui, code: &qrcode::QrCode) {
    let modules = code.width();
    let scale = (220.0 / (modules + 8) as f32).floor().max(2.0);
    let side = (modules + 8) as f32 * scale;
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
        ui.painter().rect_filled(rect, 8.0, egui::Color32::WHITE);
        for y in 0..modules {
            for x in 0..modules {
                if code[(x, y)] == qrcode::Color::Dark {
                    let pos = rect.min + egui::vec2((x + 4) as f32 * scale, (y + 4) as f32 * scale);
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(pos, egui::vec2(scale, scale)),
                        0.0,
                        egui::Color32::BLACK,
                    );
                }
            }
        }
    });
}

enum ForgetChoice {
    Forget,
    Confirm,
    Cancel,
}

fn forget_choice(ui: &mut egui::Ui, name: &str, pending: bool) -> Option<ForgetChoice> {
    let mut choice = None;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(name).color(TEXT));
        if !pending && ui.button("Forget").clicked() {
            choice = Some(ForgetChoice::Forget);
        }
    });
    if pending {
        ui.horizontal(|ui| {
            if ui.button("Yes, forget").clicked() {
                choice = Some(ForgetChoice::Confirm);
            }
            if ui.button("Cancel").clicked() {
                choice = Some(ForgetChoice::Cancel);
            }
        });
    }
    choice
}

const CANVAS: egui::Color32 = egui::Color32::from_rgb(247, 248, 247);
const SURFACE: egui::Color32 = egui::Color32::WHITE;
const TEXT: egui::Color32 = egui::Color32::from_rgb(30, 39, 35);
const SECONDARY: egui::Color32 = egui::Color32::from_rgb(83, 96, 88);
const ACTION: egui::Color32 = egui::Color32::from_rgb(38, 115, 77);
const SELECTION: egui::Color32 = egui::Color32::from_rgb(217, 236, 223);
const LINE: egui::Color32 = egui::Color32::from_rgb(220, 229, 223);
const DANGER: egui::Color32 = egui::Color32::from_rgb(166, 48, 36);
const SOFT: egui::Color32 = egui::Color32::from_rgb(235, 241, 237);

/// UDP connect selects a local route without sending packets or discovering peers.
fn local_endpoint() -> String {
    let ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("192.0.2.1:9")?;
            socket.local_addr()
        })
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    format!("{ip}:5000")
}
