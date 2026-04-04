package options

// TemplateOptions groups operator-facing settings that should be equally easy
// to drive from JSON templates, CLI flags, and a future GUI.
type TemplateOptions struct {
	Execution ExecutionOptions `json:"execution,omitempty"`
	Network   NetworkOptions   `json:"network,omitempty"`
	Scan      ScanOptions      `json:"scan,omitempty"`
	Sensors   SensorOptions    `json:"sensors,omitempty"`
	Storage   StorageOptions   `json:"storage,omitempty"`
}

type ExecutionOptions struct {
	ContinueOnError      *bool  `json:"continue_on_error,omitempty"`
	RetainPartialResults *bool  `json:"retain_partial_results,omitempty"`
	ReevaluateAmbiguous  *bool  `json:"reevaluate_ambiguous,omitempty"`
	ReevaluateAfter      string `json:"reevaluate_after,omitempty"`
}

type NetworkOptions struct {
	ActiveInterface  string `json:"active_interface,omitempty"`
	PassiveInterface string `json:"passive_interface,omitempty"`
}

type ScanOptions struct {
	PortTemplate string `json:"port_template,omitempty"`
}

type SensorOptions struct {
	PassiveMode   string `json:"passive_mode,omitempty"`
	AutoStartZeek *bool  `json:"auto_start_zeek,omitempty"`
	ZeekLogDir    string `json:"zeek_log_dir,omitempty"`
}

type StorageOptions struct {
	Project string `json:"project,omitempty"`
	DataDir string `json:"data_dir,omitempty"`
	DBPath  string `json:"db_path,omitempty"`
}

// EffectiveOptions is the normalized, defaulted option set used during a run.
type EffectiveOptions struct {
	ContinueOnError      bool   `json:"continue_on_error"`
	RetainPartialResults bool   `json:"retain_partial_results"`
	ReevaluateAmbiguous  bool   `json:"reevaluate_ambiguous"`
	ReevaluateAfter      string `json:"reevaluate_after"`
	ActiveInterface      string `json:"active_interface,omitempty"`
	PassiveInterface     string `json:"passive_interface,omitempty"`
	PortTemplate         string `json:"port_template,omitempty"`
	PassiveMode          string `json:"passive_mode,omitempty"`
	AutoStartZeek        bool   `json:"auto_start_zeek"`
	ZeekLogDir           string `json:"zeek_log_dir,omitempty"`
	Project              string `json:"project,omitempty"`
	DataDir              string `json:"data_dir,omitempty"`
	DBPath               string `json:"db_path,omitempty"`
}

func DefaultEffectiveOptions() EffectiveOptions {
	return EffectiveOptions{
		ContinueOnError:      true,
		RetainPartialResults: true,
		ReevaluateAmbiguous:  true,
		ReevaluateAfter:      "30m",
		PassiveMode:          "auto",
		AutoStartZeek:        true,
	}
}

func Resolve(base TemplateOptions, overrides TemplateOptions) EffectiveOptions {
	effective := DefaultEffectiveOptions()

	mergeTemplateOptions(&effective, base)
	mergeTemplateOptions(&effective, overrides)

	return effective
}

func mergeTemplateOptions(dst *EffectiveOptions, src TemplateOptions) {
	if src.Execution.ContinueOnError != nil {
		dst.ContinueOnError = *src.Execution.ContinueOnError
	}
	if src.Execution.RetainPartialResults != nil {
		dst.RetainPartialResults = *src.Execution.RetainPartialResults
	}
	if src.Execution.ReevaluateAmbiguous != nil {
		dst.ReevaluateAmbiguous = *src.Execution.ReevaluateAmbiguous
	}
	if src.Execution.ReevaluateAfter != "" {
		dst.ReevaluateAfter = src.Execution.ReevaluateAfter
	}

	if src.Network.ActiveInterface != "" {
		dst.ActiveInterface = src.Network.ActiveInterface
	}
	if src.Network.PassiveInterface != "" {
		dst.PassiveInterface = src.Network.PassiveInterface
	}

	if src.Scan.PortTemplate != "" {
		dst.PortTemplate = src.Scan.PortTemplate
	}

	if src.Sensors.PassiveMode != "" {
		dst.PassiveMode = src.Sensors.PassiveMode
	}
	if src.Sensors.AutoStartZeek != nil {
		dst.AutoStartZeek = *src.Sensors.AutoStartZeek
	}
	if src.Sensors.ZeekLogDir != "" {
		dst.ZeekLogDir = src.Sensors.ZeekLogDir
	}

	if src.Storage.Project != "" {
		dst.Project = src.Storage.Project
	}
	if src.Storage.DataDir != "" {
		dst.DataDir = src.Storage.DataDir
	}
	if src.Storage.DBPath != "" {
		dst.DBPath = src.Storage.DBPath
	}
}
