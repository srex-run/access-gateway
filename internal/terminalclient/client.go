// Package terminalclient runs the native database client in the session worker.
// The child receives only its temporary login and local proxy identity.
// Its filesystem and network are confined before any client code is executed.
package terminalclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
)

var ErrUnavailable = errors.New("terminal client or isolation is unavailable")

const trustDirectory = "ca-certs"

// Bridge serves an already accepted client connection through the worker's
// audited proxy. It must finish when ctx is cancelled. All connections,
// including driver monitoring/reconnects, receive the same approved target.
type Bridge func(context.Context, net.Conn) error

type Options struct {
	Protocol          string
	Account           string
	Certificate       string
	ClientCertificate string
	ClientKey         string
	Start             terminal.Message
}

type launchSpec struct {
	ClientIdentity bool
	DiagnosticFD   int
	Protocol       string
	Account        string
	Password       string
	Database       string
	AuthSource     string
	Directory      string
	Port           string
}

// Run owns the PTY, the isolated client process group, its temporary directory,
// and every proxy connection. No subprocess survives the browser connection.
func Run(ctx context.Context, options Options, stream terminal.Stream, bridge Bridge) error {
	if !options.Start.ValidFor(options.Protocol) || (options.Account == "" && options.Protocol != "http") || options.Protocol == "ssh" || bridge == nil || options.Certificate == "" || options.ClientCertificate == "" || options.ClientKey == "" {
		return ErrUnavailable
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	directory, err := newClientDirectory()
	if err != nil {
		return ErrUnavailable
	}
	defer os.RemoveAll(directory)
	// Keep any OpenSSL default trust lookup inside this terminal's private
	// directory, in addition to passing the CA explicitly to each client.
	if err = os.Mkdir(filepath.Join(directory, trustDirectory), 0700); err != nil {
		return ErrUnavailable
	}
	if options.ClientCertificate != "" || options.ClientKey != "" {
		if options.ClientCertificate == "" || options.ClientKey == "" {
			return ErrUnavailable
		}
		if err = os.WriteFile(filepath.Join(directory, "client.pem"), []byte(options.ClientCertificate+options.ClientKey), 0600); err != nil {
			return ErrUnavailable
		}
	}
	if err = os.WriteFile(filepath.Join(directory, "ca.pem"), []byte(options.Certificate), 0600); err != nil {
		return ErrUnavailable
	}
	if err = os.WriteFile(filepath.Join(directory, "mongodb.js"), []byte(mongoBootstrap), 0600); err != nil {
		return ErrUnavailable
	}
	if err = os.WriteFile(filepath.Join(directory, "http.sh"), []byte(httpBootstrap), 0600); err != nil {
		return ErrUnavailable
	}
	spec := launchSpec{Protocol: options.Protocol, Account: options.Account, Password: options.Start.Password,
		Database: options.Start.Database, AuthSource: options.Start.AuthSource, Directory: directory, Port: "1"}
	spec.ClientIdentity = options.ClientKey != ""
	options.ClientKey = ""
	input, inputWriter, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer input.Close()
	defer inputWriter.Close()
	diagnostic, diagnosticWriter, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer diagnostic.Close()
	defer diagnosticWriter.Close()
	executable, err := os.Executable()
	if err != nil {
		return ErrUnavailable
	}
	command := exec.Command(executable, "terminal-client")
	command.Dir = directory
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	command.ExtraFiles = []*os.File{input}
	ptmx, tty, err := pty.Open()
	if err != nil {
		return ErrUnavailable
	}
	defer ptmx.Close()
	defer tty.Close()
	if err = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(options.Start.Rows), Cols: uint16(options.Start.Cols)}); err != nil {
		return ErrUnavailable
	}
	command.Stdin, command.Stdout, command.Stderr = tty, tty, tty
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	// Allocate the PTY before building the sandbox so terminal control is
	// permitted for this exact device, never another user's terminal.
	finishNetwork, err := prepareCommand(ctx, command, &spec, bridge, func() { cancel(context.Canceled) })
	if err != nil {
		return ErrUnavailable
	}
	defer finishNetwork()
	// Append after the platform's isolation descriptors (Linux uses fd 4).
	// Only our helper may write this pipe; it is closed when exec starts the CLI.
	spec.DiagnosticFD = 3 + len(command.ExtraFiles)
	command.ExtraFiles = append(command.ExtraFiles, diagnosticWriter)
	// The helper gets credentials over an inherited pipe, never argv or the
	// worker's environment. Its clean environment is constructed after isolation.
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- json.NewEncoder(inputWriter).Encode(spec)
		_ = inputWriter.Close()
	}()
	if err = command.Start(); err != nil {
		_ = input.Close()
		<-writeDone
		return ErrUnavailable
	}
	_ = tty.Close()
	_ = diagnosticWriter.Close()
	_ = input.Close()
	if err = <-writeDone; err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return ErrUnavailable
	}
	spec.Password, options.Start.Password = "", ""
	var killOnce sync.Once
	killGroup := func() { killOnce.Do(func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }) }
	stop := context.AfterFunc(ctx, func() {
		killGroup()
		_ = ptmx.Close()
		_ = stream.Close()
	})
	defer stop()
	defer killGroup()
	stream.SetResize(func(rows, cols int) error {
		return pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	})
	if err = stream.Send(terminal.Message{Type: "ready"}); err != nil {
		cancel(err)
		_ = command.Wait()
		return err
	}
	inputDone, outputDone := make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(inputDone)
		_, err := io.Copy(ptmx, stream)
		if err == nil {
			err = terminal.ErrTerminalClosed
		}
		cancel(err)
	}()
	go func() {
		_, e := io.Copy(stream, ptmx)
		outputDone <- e
		// A close-frame acknowledgement can beat the input goroutine. Let
		// that reader classify the close code instead of cancelling on the
		// resulting ErrCloseSent and losing a deliberate browser close.
		if e != nil && !errors.Is(e, syscall.EIO) && !errors.Is(e, websocket.ErrCloseSent) {
			cancel(e)
		}
	}()
	waitErr := command.Wait()
	// Killing the group also removes children created by CLI shell escapes.
	killGroup()
	outputErr := <-outputDone
	if errors.Is(outputErr, syscall.EIO) || errors.Is(outputErr, os.ErrClosed) {
		outputErr = nil // Linux PTY EOF is EIO after the last slave closes.
	}
	tlsErr := readTLSMaterialError(diagnostic)
	resultErr := clientExitError(waitErr, outputErr, tlsErr, context.Cause(ctx))
	if resultErr == nil {
		resultErr = stream.Send(terminal.Message{Type: "exit"})
	} else if ctx.Err() == nil && terminal.CloseReason(resultErr) == "" {
		message := "客户端已退出，请检查终端提示、登录信息和资产连接配置"
		if tlsErr != nil {
			message = tlsErr.Error()
		} else if waitErr != nil && command.ProcessState != nil {
			// ProcessState contains only an exit code/signal, never credentials
			// or argv. Loader crashes can occur before any terminal output.
			message = "客户端异常退出（" + command.ProcessState.String() + "），请检查终端运行环境、登录信息和资产连接配置"
		}
		_ = stream.Send(terminal.Message{Type: "error", Data: message})
	}
	_ = stream.Close()
	cancel(nil)
	<-inputDone
	return resultErr
}

func clientExitError(waitErr, outputErr, setupErr, cause error) error {
	if terminal.CloseReason(cause) != "" && setupErr == nil && (outputErr == nil || errors.Is(outputErr, os.ErrClosed) || errors.Is(outputErr, net.ErrClosed) || errors.Is(outputErr, io.ErrClosedPipe) || errors.Is(outputErr, syscall.EPIPE) || errors.Is(outputErr, websocket.ErrCloseSent)) {
		var exit *exec.ExitError
		killed := false
		if errors.As(waitErr, &exit) {
			status, ok := exit.Sys().(syscall.WaitStatus)
			killed = ok && status.Signaled() && status.Signal() == syscall.SIGKILL
		}
		if waitErr == nil || killed {
			return cause
		}
	}
	return errors.Join(setupErr, waitErr, outputErr, cause)
}

// ChildMain is called before loading any worker settings. The login travels
// through fd 3, and only this child obtains database-specific environment vars.
func ChildMain() int {
	input := os.NewFile(3, "terminal-login")
	if input == nil {
		return 1
	}
	var spec launchSpec
	err := json.NewDecoder(io.LimitReader(input, terminal.MaxMessage)).Decode(&spec)
	_ = input.Close()
	if err != nil || !filepath.IsAbs(spec.Directory) || (spec.Account == "" && spec.Protocol != "http") || strings.ContainsRune(spec.Account, 0) {
		return 1
	}
	command, args, environment, err := clientCommand(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "未安装对应数据库客户端，请使用包含站内客户端的新镜像；本地开发请安装对应客户端。")
		return 1
	}
	if err = isolate(spec); err != nil {
		fmt.Fprintln(os.Stderr, "无法启用终端进程隔离，请检查 worker 的内核和运行环境。")
		return 1
	}
	if spec.DiagnosticFD < 4 || spec.DiagnosticFD > 5 {
		return 1
	}
	diagnostic := os.NewFile(uintptr(spec.DiagnosticFD), "terminal-diagnostic")
	defer diagnostic.Close()
	syscall.CloseOnExec(spec.DiagnosticFD)
	if err := checkTLSMaterial(spec.Directory, spec.ClientIdentity); err != nil {
		// Only fixed file roles/error categories cross this pipe. Never send
		// PEM contents, parser errors, credentials or the client environment.
		_ = json.NewEncoder(diagnostic).Encode(err)
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if err = syscall.Exec(command, append([]string{command}, args...), environment); err != nil {
		fmt.Fprintln(os.Stderr, "客户端启动失败。")
		return 1
	}
	return 0
}

func clientCommand(spec launchSpec) (string, []string, []string, error) {
	if !(terminal.Message{Type: "start", Cols: 80, Rows: 24, Password: spec.Password, Database: spec.Database, AuthSource: spec.AuthSource}).ValidFor(spec.Protocol) {
		return "", nil, nil, ErrUnavailable
	}
	ca := filepath.Join(spec.Directory, "ca.pem")
	identity := filepath.Join(spec.Directory, "client.pem")
	locale := "C.UTF-8"
	if runtime.GOOS == "darwin" {
		locale = "en_US.UTF-8"
	}
	environment := []string{
		"PATH=" + os.Getenv("PATH"), "LANG=" + locale, "LC_ALL=" + locale, "TERM=xterm-256color",
		"HOME=" + spec.Directory, "TMPDIR=" + spec.Directory,
		"SSL_CERT_FILE=" + ca, "SSL_CERT_DIR=" + filepath.Join(spec.Directory, trustDirectory),
	}
	var binary string
	var args []string
	switch spec.Protocol {
	case "mysql":
		binary = "mariadb"
		if _, err := exec.LookPath(binary); err != nil {
			binary = "mysql"
		}
		// Hide the welcome banner while keeping interactive line editing,
		// completion and tabular results. --silent does not prevent the native
		// client's version/syntax probes; the proxy audits their startup origin.
		args = []string{"--no-defaults", "--protocol=TCP", "--host=127.0.0.1", "--port=" + spec.Port, "--user=" + spec.Account, "--skip-reconnect", "--local-infile=0", "--silent", "--table", "--prompt=mysql> "}
		if binary == "mariadb" {
			args = append(args, "--ssl", "--ssl-ca="+ca, "--ssl-verify-server-cert")
		} else {
			args = append(args, "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca="+ca)
		}
		if spec.Database != "" {
			args = append(args, "--database="+spec.Database)
		}
		if spec.ClientIdentity {
			args = append(args, "--ssl-cert="+identity, "--ssl-key="+identity)
		}
		environment = append(environment, "MYSQL_PWD="+spec.Password, "MYSQL_HISTFILE=/dev/null")
	case "postgresql":
		binary = "psql"
		if spec.Database == "" {
			spec.Database = "postgres"
		}
		args = []string{"--no-psqlrc", "--no-password", "--host=127.0.0.1", "--port=" + spec.Port, "--username=" + spec.Account, "--dbname=" + spec.Database}
		// The audit proxy terminates TLS on each leg and advertises non-PLUS
		// SCRAM. libpq's default "prefer" sends a y,, header in that case,
		// which a TLS-enabled PostgreSQL backend rejects as a downgrade.
		environment = append(environment, "PGPASSWORD="+spec.Password, "PGSSLMODE=verify-full", "PGSSLROOTCERT="+ca, "PGCONNECT_TIMEOUT=15", "PGGSSENCMODE=disable", "PGCHANNELBINDING=disable", "PSQL_HISTORY=/dev/null", "PSQL_PAGER=", "PAGER=")
		if spec.ClientIdentity {
			environment = append(environment, "PGSSLCERT="+identity, "PGSSLKEY="+identity)
		}
	case "redis":
		binary = "redis-cli"
		if spec.Database == "" {
			spec.Database = "0"
		}
		args = []string{"-h", "127.0.0.1", "-p", spec.Port, "--tls", "--cacert", ca, "--sni", "127.0.0.1", "--user", spec.Account, "-n", spec.Database}
		if spec.ClientIdentity {
			args = append(args, "--cert", identity, "--key", identity)
		}
		environment = append(environment, "REDISCLI_AUTH="+spec.Password, "REDISCLI_HISTFILE=/dev/null")
	case "mongodb":
		binary = "mongosh"
		if spec.Database == "" {
			spec.Database = "test"
		}
		if spec.AuthSource == "" {
			spec.AuthSource = "admin"
		}
		args = []string{"--nodb", "--norc", "--quiet", "--shell", filepath.Join(spec.Directory, "mongodb.js")}
		login := map[string]string{"user": spec.Account, "password": spec.Password, "database": spec.Database, "authSource": spec.AuthSource, "port": spec.Port, "ca": ca}
		if spec.ClientIdentity {
			login["certificate"] = identity
		}
		value, _ := json.Marshal(login)
		environment = append(environment, "GATEWAY_TERMINAL_LOGIN="+string(value), "MONGOSH_DISABLE_TELEMETRY=1")
		clear(value)
	case "http":
		binary = "bash"
		args = []string{"--noprofile", "--rcfile", filepath.Join(spec.Directory, "http.sh"), "-i"}
		environment = append(environment, "GATEWAY_HTTP_PORT="+spec.Port, "HISTFILE=/dev/null")
		if spec.Account != "" {
			// curl's config parser accepts double-quoted escaped values. Credentials
			// stay in process memory and reach curl over a pipe, never a file/argv.
			quote := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
			login := "user = \"" + quote.Replace(spec.Account+":"+spec.Password) + "\"\n"
			environment = append(environment, "GATEWAY_HTTP_LOGIN="+login)
		}
	default:
		return "", nil, nil, ErrUnavailable
	}
	path, err := exec.LookPath(binary)
	return path, args, environment, err
}

const mongoBootstrap = `(() => {
const login = JSON.parse(process.env.GATEWAY_TERMINAL_LOGIN);
delete process.env.GATEWAY_TERMINAL_LOGIN;
config.set('enableTelemetry', false);
config.set('historyLength', 0);
const uri = 'mongodb://' + encodeURIComponent(login.user) + ':' + encodeURIComponent(login.password) +
  '@127.0.0.1:' + login.port + '/' + encodeURIComponent(login.database) +
  '?authSource=' + encodeURIComponent(login.authSource) + '&directConnection=true&tls=true&tlsCAFile=' + encodeURIComponent(login.ca) +
  '&maxPoolSize=1&minPoolSize=0&serverSelectionTimeoutMS=15000&connectTimeoutMS=15000' +
  (login.certificate ? '&tlsCertificateKeyFile=' + encodeURIComponent(login.certificate) : '');
try { db = connect(uri); }
catch { throw new Error('MongoDB 连接失败，请检查登录信息、目标连接配置与审计记录。'); }
finally { login.password = ''; }
})();
`

const httpBootstrap = `PS1='http> '
# The Linux sandbox denies setpgid, so bash's job control hands the terminal
# to a process group nothing ever joined and Ctrl-C reaches nobody. Without
# job control every command stays in the shell's own group, which is also the
# group the supervisor kills on revocation, and the interrupt gets the prompt
# back. This is unconditional so a shell on a developer's machine behaves the
# way the deployed one does. A plain 'set +m' cannot work here: bash restores
# the job-control state it saved before reading this file, so the switch has
# to be thrown once the first prompt is being drawn.
PROMPT_COMMAND='set +m'
HISTFILE=/dev/null
set +o history
request() {
  local method="$1" path="$2"
  shift 2
  case "$path" in /*) ;; *) printf '路径必须以 / 开头\n'; return 1 ;; esac
  local identity=()
  if [ -f "$HOME/client.pem" ]; then identity=(--cert "$HOME/client.pem" --key "$HOME/client.pem"); fi
  if [ -n "$GATEWAY_HTTP_LOGIN" ]; then
    printf '%s' "$GATEWAY_HTTP_LOGIN" | command curl -q --config - --silent --show-error --include --cacert "$HOME/ca.pem" "${identity[@]}" --request "$method" "$@" --url "https://127.0.0.1:$GATEWAY_HTTP_PORT$path"
  else
    command curl -q --silent --show-error --include --cacert "$HOME/ca.pem" "${identity[@]}" --request "$method" "$@" --url "https://127.0.0.1:$GATEWAY_HTTP_PORT$path"
  fi
  printf '\n'
}
GET() { request GET "$@"; }
POST() { request POST "$@"; }
PUT() { request PUT "$@"; }
PATCH() { request PATCH "$@"; }
DELETE() { request DELETE "$@"; }
HEAD() { request HEAD "$@" --head; }
OPTIONS() { request OPTIONS "$@"; }
printf 'HTTP 请求终端。示例：GET /health\nPOST /api -H "Content-Type: application/json" --data '\''{"key":"value"}'\''\n输入 exit 退出。\n'
`
