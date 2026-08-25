package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"ipv4Bypass/internal/model"
)

// WriteJSON emits the complete report as a single pretty-printed document.
func WriteJSON(path string, rep *model.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return err
	}
	return f.Close()
}

// NDJSON writes one host result per line as scanning progresses.
func NDJSON(w io.Writer, res *model.HostResult) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// WriteCSV emits findings as CSV rows for spreadsheet/SIEM ingestion.
func WriteCSV(path string, rep *model.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, "severity,category,protocol,port,ipv4,ipv6,mac,hostname,detail"); err != nil {
		return err
	}
	for _, fd := range rep.Findings {
		h := fd.Host
		row := []string{
			string(fd.Severity),
			string(fd.Category),
			string(fd.Protocol),
			strconv.Itoa(fd.Port),
			h.IPv4,
			h.PrimaryIPv6(),
			h.MAC,
			firstStr(h.MDNSName, h.HostnameV4, h.HostnameV6),
			fd.Detail,
		}
		for i, cell := range row {
			row[i] = `"` + escapeQuotes(cell) + `"`
		}
		if _, err := fmt.Fprintln(f, joinNonEmpty(row, ",")); err != nil {
			return err
		}
	}
	return f.Close()
}

func escapeQuotes(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"')
		}
		out = append(out, s[i])
	}
	return string(out)
}
