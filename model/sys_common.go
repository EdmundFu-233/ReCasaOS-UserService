package model

type CommonModel struct {
	RuntimePath string
	// CORSOrigins is a comma-separated list of exact HTTP(S) origins allowed
	// to use browser credentials. Empty means same-origin only: no CORS
	// headers are emitted and no preflight is answered.
	CORSOrigins string
}

type APPModel struct {
	LogPath      string
	LogSaveName  string
	LogFileExt   string
	UserDataPath string
	DBPath       string
}

type Result struct {
	Success int         `json:"success" example:"200"`
	Message string      `json:"message" example:"ok"`
	Data    interface{} `json:"data" example:"返回结果"`
}
