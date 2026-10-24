package mobile

import (
	"encoding/base64"
	"encoding/json"
	"sync"
)

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeBase64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// Host is everything the Android shell contributes. Keeping it behind an
// interface is what lets the whole application be tested with `go test`.
type Host interface {
	// PickFiles opens the system file picker and returns the chosen files.
	PickFiles() []PickedFile
	// ReadClipboard / Copy round-trip the system clipboard. Copy reports whether
	// the platform accepted the write.
	ReadClipboard() string
	Copy(text string) bool
	// Share hands a real .txt file to the share sheet.
	Share(name, text string)
	// Save opens the system "create document" flow.
	Save(name, text string)
	// OpenExternal opens a Play Store listing or a link in another app.
	OpenExternal(target string)
	// LoadPrefs / SavePrefs persist the settings blob.
	LoadPrefs() string
	SavePrefs(json string)
	// SetDark tells the shell which system bar style suits the current theme.
	SetDark(dark bool)
	// Haptic is a short confirmation tick.
	Haptic()
}

// App is the whole application: the queue, the settings and every action the
// interface can trigger. It is safe for concurrent use because the interface
// may call in from the render loop while the worker decrypts.
type App struct {
	mu       sync.Mutex
	host     Host
	engine   Engine
	settings Settings
	jobs     []*Job
	notices  []string
	nextID   int64

	passwordJob  int64
	passwordErr  string
	engineErr    string
	settingsOpen bool

	queue chan int64
	gates map[int64]chan string
	ready bool
}

// New builds the application, restores preferences and starts the worker that
// drains the queue one file at a time.
func New(host Host) *App {
	a := &App{
		host:     host,
		settings: defaultSettings(),
		queue:    make(chan int64, 256),
		gates:    map[int64]chan string{},
	}
	a.settings = a.loadPrefs()
	a.ready = true

	go a.worker()
	return a
}

func (a *App) loadPrefs() Settings {
	raw := a.host.LoadPrefs()
	if raw == "" {
		return defaultSettings()
	}
	s := defaultSettings()
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return defaultSettings()
	}
	if s.Theme != "light" && s.Theme != "dark" {
		s.Theme = "system"
	}
	if s.Locale != "fa" {
		s.Locale = "en"
	}
	return s
}

func (a *App) savePrefs() {
	raw, err := json.Marshal(a.settings)
	if err != nil {
		return
	}
	a.host.SavePrefs(string(raw))
}

func (a *App) worker() {
	for id := range a.queue {
		a.process(id)
	}
}

func (a *App) enqueue(name string, data []byte, fromClip bool) int64 {
	a.mu.Lock()
	a.nextID++
	job := &Job{
		ID:       a.nextID,
		Name:     SanitizeName(name),
		Size:     len(data),
		FromClip: fromClip,
		Phase:    PhaseQueued,
		Wrap:     true,
		data:     data,
	}
	a.jobs = append(a.jobs, job)
	a.mu.Unlock()
	return job.ID
}

func (a *App) job(id int64) *Job {
	for _, j := range a.jobs {
		if j.ID == id {
			return j
		}
	}
	return nil
}

func (a *App) process(id int64) {
	a.mu.Lock()
	job := a.job(id)
	if job == nil {
		a.mu.Unlock()
		return
	}
	a.update(id, func(j *Job) {
		j.Phase = PhaseInspecting
		j.Err = ""
		j.promptPassword = false
	})
	a.mu.Unlock()

	if !a.ready {
		a.fail(id, "the decryption engine is not ready")
		return
	}

	data := a.data(id)
	if data == nil {
		return
	}
	if len(data) > maxInputBytes {
		a.fail(id, "this file is too large to process safely")
		return
	}

	name := a.name(id)
	info := a.engine.Inspect(name, data)
	a.mu.Lock()
	a.update(id, func(j *Job) {
		j.Module = info.Module
		j.ApkAuthor = info.ApkAuthor
	})
	a.mu.Unlock()

	if !info.Supported {
		a.fail(id, "no module matches this file")
		return
	}

	password := ""
	attempts := 0
	lastErr := ""
	for {
		if (info.NeedsPassword || a.needsPassword(id)) && password == "" {
			answer, ok := a.askPassword(id, lastErr)
			if !ok {
				// Cancelled: leave the job parked so it can be resumed later.
				a.mu.Lock()
				a.update(id, func(j *Job) { j.Phase = PhaseWaitPassword; j.Err = "" })
				a.mu.Unlock()
				return
			}
			password = answer
		}

		a.mu.Lock()
		a.update(id, func(j *Job) { j.Phase = PhaseWorking })
		a.mu.Unlock()

		outcome := a.engine.Decrypt(name, data, password)
		if outcome.OK {
			a.succeed(id, outcome)
			return
		}
		if info.NeedsPassword && attempts < maxPasswordRetries {
			attempts++
			password = ""
			lastErr = outcome.Err
			continue
		}
		a.fail(id, outcome.Err)
		return
	}
}

func (a *App) data(id int64) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	job := a.job(id)
	if job == nil {
		return nil
	}
	return job.data
}

func (a *App) name(id int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if job := a.job(id); job != nil {
		return job.Name
	}
	return ""
}

func (a *App) needsPassword(id int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	job := a.job(id)
	return job != nil && job.promptPassword
}

// askPassword parks the queue until the user answers, reporting any error left
// over from the previous attempt.
func (a *App) askPassword(id int64, lastErr string) (string, bool) {
	gate := make(chan string, 1)

	a.mu.Lock()
	a.gates[id] = gate
	a.passwordJob = id
	a.passwordErr = lastErr
	a.mu.Unlock()

	answer := <-gate

	a.mu.Lock()
	delete(a.gates, id)
	if a.passwordJob == id {
		a.passwordJob = 0
		a.passwordErr = ""
	}
	a.mu.Unlock()

	return answer, answer != ""
}

func (a *App) succeed(id int64, outcome DecryptOutcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.update(id, func(j *Job) {
		j.Phase = PhaseDone
		j.Text = outcome.Text
		j.OutName = outcome.FileName
		if outcome.Module != "" {
			j.Module = outcome.Module
		}
		if outcome.ApkAuthor != "" {
			j.ApkAuthor = outcome.ApkAuthor
		}
		j.Err = ""
		j.Expanded = true
		j.data = nil
	})
}

func (a *App) fail(id int64, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if reason == "" {
		reason = "decryption failed"
	}
	a.update(id, func(j *Job) { j.Phase = PhaseFailed; j.Err = reason })
}

// update mutates one job. Callers must already hold a.mu.
func (a *App) update(id int64, fn func(*Job)) {
	if job := a.job(id); job != nil {
		fn(job)
	}
}

// -- actions ----------------------------------------------------------------

// Pick opens the system picker and queues whatever comes back.
func (a *App) Pick() {
	files := a.host.PickFiles()
	for _, file := range files {
		data, err := decodeBase64(file.B64)
		if err != nil {
			continue
		}
		name := SanitizeName(file.Name)
		if name == "config" && file.Name != "" {
			name = SanitizeName(file.Name)
		}
		a.enqueue(name, data, false)
	}
	a.drain()
}

// Paste turns the clipboard into a config when it holds one.
func (a *App) Paste() {
	candidate, ok := ParseClipboard(a.host.ReadClipboard())
	if !ok {
		a.notice("paste_unsupported")
		return
	}
	data, err := decodeBase64(candidate.B64)
	if err != nil {
		a.notice("paste_unsupported")
		return
	}
	a.enqueue(candidate.Name, data, true)
	a.drain()
}

// Add queues raw bytes, which is also how the desktop and test builds feed the
// same pipeline.
func (a *App) Add(name string, data []byte) {
	a.enqueue(name, data, false)
	a.drain()
}

func (a *App) drain() {
	a.mu.Lock()
	ids := make([]int64, 0, len(a.jobs))
	for _, j := range a.jobs {
		if j.Phase == PhaseQueued {
			ids = append(ids, j.ID)
		}
	}
	a.mu.Unlock()
	for _, id := range ids {
		select {
		case a.queue <- id:
		default:
		}
	}
}

// SubmitPassword answers the open password prompt.
func (a *App) SubmitPassword(value string) {
	a.mu.Lock()
	gate := a.gates[a.passwordJob]
	a.mu.Unlock()
	if gate != nil {
		gate <- value
	}
}

// CancelPassword dismisses the prompt and parks the job.
func (a *App) CancelPassword() {
	a.mu.Lock()
	gate := a.gates[a.passwordJob]
	a.mu.Unlock()
	if gate != nil {
		gate <- ""
	}
}

func (a *App) Remove(id int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.jobs[:0]
	for _, j := range a.jobs {
		if j.ID != id {
			kept = append(kept, j)
		}
	}
	a.jobs = kept
	if gate, ok := a.gates[id]; ok {
		gate <- ""
		delete(a.gates, id)
	}
	if a.passwordJob == id {
		a.passwordJob = 0
		a.passwordErr = ""
	}
}

func (a *App) Clear() {
	a.mu.Lock()
	ids := make([]int64, 0, len(a.jobs))
	for _, j := range a.jobs {
		ids = append(ids, j.ID)
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.Remove(id)
	}
}

func (a *App) Retry(id int64) {
	a.mu.Lock()
	job := a.job(id)
	if job == nil || (job.Phase != PhaseFailed && job.Phase != PhaseWaitPassword) {
		a.mu.Unlock()
		return
	}
	needs := job.Phase == PhaseWaitPassword
	a.update(id, func(j *Job) {
		j.Phase = PhaseQueued
		j.Err = ""
		j.promptPassword = needs
	})
	a.mu.Unlock()
	a.drain()
}

func (a *App) ToggleExpand(id int64) { a.flip(id, func(j *Job) { j.Expanded = !j.Expanded }) }
func (a *App) ToggleWrap(id int64)   { a.flip(id, func(j *Job) { j.Wrap = !j.Wrap }) }

func (a *App) flip(id int64, fn func(*Job)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.update(id, fn)
}

func (a *App) Copy(id int64) {
	text, _, ok := a.payload(id)
	if !ok {
		a.notice("msg_nothing_to_copy")
		return
	}
	if a.host.Copy(text) {
		a.host.Haptic()
		a.notice("msg_copied")
	} else {
		a.notice("msg_copy_failed")
	}
}

func (a *App) Share(id int64) {
	if text, name, ok := a.payload(id); ok {
		a.host.Share(name, text)
		return
	}
	a.notice("msg_nothing_to_copy")
}

func (a *App) Save(id int64) {
	if text, name, ok := a.payload(id); ok {
		a.host.Save(name, text)
		return
	}
	a.notice("msg_nothing_to_copy")
}

func (a *App) OpenAuthor(id int64) {
	a.mu.Lock()
	target := ""
	if job := a.job(id); job != nil {
		target = job.ApkAuthor
	}
	a.mu.Unlock()
	if target != "" {
		a.host.OpenExternal(target)
	}
}

func (a *App) payload(id int64) (text, name string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	job := a.job(id)
	if job == nil || job.Phase != PhaseDone {
		return "", "", false
	}
	return job.Text, OutputFileName(job.Name, job.OutName), true
}

// -- settings ---------------------------------------------------------------

func (a *App) SetTheme(theme string) {
	if theme != "light" && theme != "dark" && theme != "system" {
		return
	}
	a.mu.Lock()
	a.settings.Theme = theme
	a.mu.Unlock()
	a.savePrefs()
	a.syncSystemBars()
}

func (a *App) SetLocale(locale string) {
	if locale != "en" && locale != "fa" {
		return
	}
	a.mu.Lock()
	a.settings.Locale = locale
	a.mu.Unlock()
	a.savePrefs()
}

func (a *App) OpenGithub() { a.host.OpenExternal("https://github.com/FrontierTM/Pantegnos") }
func (a *App) OpenWebsite() {
	a.host.OpenExternal("https://frontiertm.github.io/Pantegnos/")
}

func (a *App) OpenSettings()  { a.setSettingsOpen(true) }
func (a *App) CloseSettings() { a.setSettingsOpen(false) }

func (a *App) setSettingsOpen(open bool) {
	a.mu.Lock()
	a.settingsOpen = open
	a.mu.Unlock()
}

// ToggleTheme flips the resolved appearance rather than stepping through the
// three states: stepping system -> dark is a visual no-op whenever the system is
// already dark.
func (a *App) ToggleTheme() {
	a.mu.Lock()
	theme := a.settings.Theme
	a.mu.Unlock()
	if theme == "dark" || (theme == "system" && a.dark()) {
		a.SetTheme("light")
		return
	}
	a.SetTheme("dark")
}

func (a *App) syncSystemBars() {
	a.host.SetDark(a.dark())
}

// systemPrefersDark is replaced by the platform entry point; the default keeps
// this package testable off-device.
var systemPrefersDark = func() bool { return true }

// dark reports the resolved appearance, so the shell can tint the system bars
// even when the user picked "system".
func (a *App) dark() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.darkLocked()
}

// darkLocked is dark for callers that already hold a.mu; sync.Mutex is not
// reentrant, so Snapshot must not go through dark().
func (a *App) darkLocked() bool {
	if a.settings.Theme == "light" {
		return false
	}
	if a.settings.Theme == "dark" {
		return true
	}
	return systemPrefersDark()
}

func (a *App) notice(key string) {
	a.mu.Lock()
	a.notices = append(a.notices, key)
	a.mu.Unlock()
}

// drainNotices returns and clears pending transient messages.
func (a *App) drainNotices() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.notices) == 0 {
		return nil
	}
	out := a.notices
	a.notices = nil
	return out
}

// -- snapshot for the view --------------------------------------------------

// Snapshot is everything the renderer needs, captured under one lock so the
// markup can never observe a half-applied change.
type Snapshot struct {
	Jobs         []*Job
	Settings     Settings
	Dark         bool
	PasswordJob  *Job
	PasswordErr  string
	Notices      []string
	Formats      []FormatEntry
	ShowSettings bool
}

// Snapshot captures the current state and drains any pending notices.
func (a *App) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	snap := Snapshot{
		Jobs:         make([]*Job, 0, len(a.jobs)),
		Settings:     a.settings,
		Dark:         a.darkLocked(),
		Formats:      supportedFormats(),
		ShowSettings: a.settingsOpen,
	}
	for _, j := range a.jobs {
		clone := *j
		clone.data = nil
		clone.promptPassword = false
		clone.lastError = ""
		snap.Jobs = append(snap.Jobs, &clone)
	}
	if a.passwordJob != 0 {
		if job := a.job(a.passwordJob); job != nil {
			clone := *job
			snap.PasswordJob = &clone
		}
	}
	snap.PasswordErr = a.passwordErr
	return snap
}

func supportedFormats() []FormatEntry {
	return []FormatEntry{
		{Ext: ".slip", Desc: "format_slip"},
		{Ext: ".ehi", Desc: "format_ehi"},
		{Ext: ".dark", Desc: "format_dark"},
		{Ext: ".hat", Desc: "format_hat"},
		{Ext: ".npvt", Desc: "format_npvt"},
		{Ext: ".npvs", Desc: "format_npvs"},
		{Ext: ".nm", Desc: "format_nm"},
		{Ext: ".happ", Desc: "format_happ"},
		{Ext: ".bpf", Desc: "format_bpf"},
		{Ext: ".tls", Desc: "format_tls"},
		{Ext: ".v2box", Desc: "format_v2box"},
		{Ext: ".zsx", Desc: "format_zsx"},
	}
}
