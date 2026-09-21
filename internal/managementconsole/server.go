package managementconsole

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

// NewApplicationHandler serves the frontend alongside the control plane without
// proxying backend requests or changing their authentication and health checks.
func NewApplicationHandler(api http.Handler, assets fs.FS) (http.Handler, error) {
	if api == nil {
		return nil, fmt.Errorf("application API handler is required")
	}
	frontend, err := newFrontendHandler(assets)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		for _, prefix := range []string{"/api", "/internal", "/callbacks", "/healthz", "/readyz", "/metrics"} {
			if request.URL.Path == prefix || strings.HasPrefix(request.URL.Path, prefix+"/") {
				api.ServeHTTP(response, request)
				return
			}
		}
		frontend.ServeHTTP(response, request)
	}), nil
}

func newFrontendHandler(assets fs.FS) (http.Handler, error) {
	if assets == nil {
		return nil, fmt.Errorf("management console assets are required")
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read console index: %w", err)
	}
	fileServer := http.FileServer(http.FS(assets))
	mux := http.NewServeMux()
	mux.Handle("/assets/", withAssetCache(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		info, statErr := fs.Stat(assets, strings.TrimPrefix(request.URL.Path, "/"))
		if statErr != nil || info.IsDir() {
			http.NotFound(response, request)
			return
		}
		fileServer.ServeHTTP(response, request)
	})))
	mux.Handle("/favicon.svg", withAssetCache(fileServer))
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.Contains(filepathAfterLastSlash(request.URL.Path), ".") {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Cache-Control", "no-store")
		if request.Method != http.MethodHead {
			_, _ = response.Write(index)
		}
	})
	return securityHeaders(mux), nil
}

func filepathAfterLastSlash(value string) string {
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func withAssetCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(response, request)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// Arco positions overlays and sizes controls using inline style attributes.
		stylePolicy := "style-src 'self'; style-src-attr 'unsafe-inline'"
		response.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; "+stylePolicy)
		response.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}
