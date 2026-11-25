// bo-offline is a sprint integration entry over the unchanged Studio server.
// No collector binaries are embedded and no capture is started by this command.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"pktpath/studio"
	"pktpath/studio/pkg/server"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	app := flag.String("app-dir", "", "required absolute isolated runtime directory")
	port := flag.Int("port", 0, "127.0.0.1 port, 0 chooses a free port")
	_ = flag.Bool("headless", true, "always headless; no browser is opened")
	lifecycle := flag.String("cordis-plugin-host", "", "explicit experimental lifecycle host; empty keeps Go default")
	pluginNode := flag.String("cordis-plugin-node", "node", "Node executable for explicit lifecycle host")
	analyzerNode := flag.String("cordis-analyzer-node", "node", "Node executable for explicit external-analyzer host")
	analyzer := flag.String("cordis-analyzer-host", "", "explicit experimental external-analyzer host")
	flag.Parse()
	if !filepath.IsAbs(*app) {
		return fmt.Errorf("--app-dir must be absolute")
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if err := os.MkdirAll(*app, 0700); err != nil {
		return err
	}
	instance := filepath.Join(*app, "instance.json")
	f, err := os.OpenFile(instance, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("reserve instance file (do not overwrite running instances): %w", err)
	}
	defer os.Remove(instance)
	defer f.Close()
	web, err := studio.WebFS()
	if err != nil {
		return err
	}
	srv := server.New(server.Options{AppDir: *app, Web: web, Logger: log.New(os.Stderr, "bo-offline ", log.LstdFlags), Version: "bo-offline-0a265193", CordisPluginHost: *lifecycle, CordisPluginNode: *pluginNode, CordisAnalyzerHost: *analyzer, CordisAnalyzerNode: *analyzerNode})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	ln, err := srv.Listen(fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	defer ln.Close()
	url := "http://" + ln.Addr().String()
	if err = json.NewEncoder(f).Encode(map[string]any{"pid": os.Getpid(), "port": srv.Port(), "url": url, "purpose": "offline integration only; no collector runtime embedded"}); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Println("PKTPATH_STUDIO_URL=" + url)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-srv.QuitRequested():
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	return nil
}
