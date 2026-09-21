package sessionproxy

import (
	"encoding/base64"
	"io"
)

// Record only server output, including echoed shell commands. A terminal is
// not a shell parser: these frames are explicitly observations, never proof of
// command execution. Base64 preserves control bytes/UTF-8 split across reads;
// the ordinary operation text is a safe, bounded preview for the audit table.
// 1024 bytes encodes below the control plane's 2048-character metadata limit.
func copySSHTerminal(dst io.Writer, src io.Reader, r *recorder, shell *operation, stream string) error {
	buf := make([]byte, 1024)
	var sequence uint64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			sequence++
			frame, err := r.begin(shell.event.ActualAccount, "terminal_output", string(buf[:n]), "", map[string]any{
				"evidence": "terminal_output", "channel_id": shell.event.OperationID,
				"stream": stream, "sequence": sequence, "encoding": "base64",
				"data": base64.StdEncoding.EncodeToString(buf[:n]),
			})
			if err != nil {
				return err
			}
			// The durable acknowledgement precedes delivery to the terminal.
			writeErr := writeAll(dst, buf[:n])
			if err = frame.end("unknown"); err != nil {
				return err
			}
			if writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
