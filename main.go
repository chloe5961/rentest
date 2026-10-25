package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	fallbackSelfMemMB         = 128
	fallbackWorkerMemMB       = 550
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 12
	workerMemPercent          = 55
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 450 * time.Millisecond
	startupOrchestrationDelay = 12 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int) {
	gwMB, workerMB = fallbackSelfMemMB, fallbackWorkerMemMB
	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		workerMB = totalMB * workerMemPercent / 100

		allowedMB := totalMB * 67 / 100
		if gwMB < 32 {
			gwMB = 32
		}
		if workerMB < 64 {
			workerMB = 64
		}
		if total := gwMB + workerMB; total > allowedMB && allowedMB >= 96 {
			gwMB = allowedMB * gatewayMemPercent / 67
			workerMB = allowedMB * workerMemPercent / 67
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", workerMB)
	return gwMB, workerMB
}

func applyMemoryCeiling(selfMB int) {
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	if rawCPU := strings.TrimSpace(getEnv("RENDER_CPU_COUNT", "")); rawCPU != "" {
		if v, err := strconv.ParseFloat(rawCPU, 64); err == nil && v > 0 {
			return v, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isRenderManagedDomain(h string) bool {
	if h == "" {
		return false
	}
	return strings.Contains(h, "onrender.com") ||
		strings.HasSuffix(h, ".render.com") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isRenderPublicDomain(h string) bool {
	return h != "" &&
		strings.Contains(h, "onrender.com") &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local")
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "frankfurt") || strings.Contains(s, "fra") || strings.Contains(s, "eu-") || strings.Contains(s, "europe") || strings.Contains(s, "germany") || strings.Contains(s, "de"):
		return "frankfurt"
	case strings.Contains(s, "oregon") || strings.Contains(s, "pdx") || strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "sjc"):
		return "oregon"
	case strings.Contains(s, "virginia") || strings.Contains(s, "iad") || strings.Contains(s, "us-east"):
		return "virginia"
	case strings.Contains(s, "ohio") || strings.Contains(s, "cmh") || strings.Contains(s, "us-central"):
		return "ohio"
	case strings.Contains(s, "singapore") || strings.Contains(s, "sin") || strings.Contains(s, "asia") || strings.Contains(s, "ap-"):
		return "singapore"
	default:
		return "frankfurt"
	}
}

func resolveInfrastructureDomains() (renderDomain, customDomain string) {
	extHostname := cleanHost(getEnv("RENDER_EXTERNAL_HOSTNAME", ""))
	extURL := cleanHost(getEnv("RENDER_EXTERNAL_URL", ""))
	publicDomain := cleanHost(getEnv("RENDER_PUBLIC_DOMAIN", getEnv("RENDER_DOMAIN", "")))
	explicitRender := cleanHost(getEnv("RENDER_DEFAULT_DOMAIN", getEnv("BERMUDA_RENDER_DOMAIN", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{explicitRender, extHostname, extURL, publicDomain} {
		if isRenderPublicDomain(candidate) {
			renderDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, extHostname, extURL, explicitRender} {
		if candidate != "" && !isRenderManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return renderDomain, customDomain
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	rn *RenderClient,
	cf *CloudflareClient,
	initialRN string,
	initialCF string,
	region string,
) {
	for i := 0; i < 40 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	renderDomain := cleanHost(initialRN)
	customDomain := cleanHost(initialCF)
	topologyUpdated := false

	syncDomains := func(newRN, newCF string) {
		cleanRN := cleanHost(newRN)
		cleanCF := cleanHost(newCF)
		if isRenderPublicDomain(cleanRN) {
			if renderDomain == "" || (!isFullRenderServiceDomain(renderDomain) && isFullRenderServiceDomain(cleanRN)) {
				if renderDomain != cleanRN {
					renderDomain = cleanRN
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isRenderManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		sup.SetInfrastructureDomains(renderDomain, customDomain, region)
		gw.SetInfrastructureDomains(renderDomain, customDomain, region)
		if cf != nil {
			if renderDomain != "" {
				cf.SetRenderOrigin(renderDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if rn != nil {
			if renderDomain != "" {
				rn.SetServiceDomain(renderDomain)
			}
			if customDomain != "" {
				rn.SetCustomDomain(customDomain)
			}
		}
	}

	if rn != nil && rn.IsConfigured() {
		if sup.IsMasterKeyAutoGenerated() && !strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			rn.PersistMasterKey(ctx, sup.MasterKey())
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
		}

		if srvDom, err := rn.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Render] Notice: Service domain lookup: %v", err)
		}
		if reg := rn.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(renderDomain, customDomain, region)
			gw.SetInfrastructureDomains(renderDomain, customDomain, region)
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			syncDomains(cf.GetRenderOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	var customDomInfo *RenderCustomDomainInfo
	var cnameRecordID string

	if customDomain != "" && (rn != nil || renderDomain != "") {
		if rn != nil && rn.IsConfigured() {
			info, err := rn.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Render] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(rn.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil && renderDomain != "" {
			certState := "PENDING_TLS"
			if probeCustomDomainTLS(ctx, customDomain, renderDomain) {
				certState = "VALID"
			}
			customDomInfo = &RenderCustomDomainInfo{
				Domain:             customDomain,
				CNAMETarget:        renderDomain,
				VerificationStatus: "unverified",
				CertificateStatus:  certState,
			}
		}
		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionRenderDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				if rn != nil && rn.IsConfigured() && !customDomInfo.RecordsVerified {
					if sleepContext(ctx, dnsPropagationSettleDelay) {
						rn.TriggerCustomDomainVerify(ctx, customDomInfo.ID, customDomInfo.Domain)
					}
				}
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetRenderOrigin(), cf.CachedZoneDomain())
	}

	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && ctx.Err() == nil {
		log.Printf("[Render] Waiting for TLS readiness on %s before enabling Cloudflare proxy...", customDomInfo.Domain)
		if rn != nil && rn.IsConfigured() {
			updatedInfo, valid := rn.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultRNCertPollWait)
			if valid && updatedInfo != nil {
				cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
			} else if ctx.Err() == nil {
				go watchAndPromoteCustomDomain(ctx, rn, cf, customDomInfo, cnameRecordID)
			}
		} else {
			go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, cnameRecordID)
		}
	}

	if rn != nil && rn.IsConfigured() && ctx.Err() == nil {
		rn.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && (topologyUpdated || rn != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: RenderDomain=%q | CloudflareDomain=%q | Region=%q",
			renderDomain, customDomain, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	rn *RenderClient,
	cf *CloudflareClient,
	info *RenderCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Render] ✓ TLS handshake verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				return
			}
			if rn != nil && rn.IsConfigured() {
				latest, err := rn.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Render] ✓ TLS validation completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(24 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (draining)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active requests...")
		httpDeadline := minTime(hardDeadline.Add(-7*time.Second), time.Now().Add(12*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listener", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listener drained")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded streams...")
		tunnelDeadline := minTime(hardDeadline.Add(-6*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Starting HTTP Edge Router...")

	gwMB, workerMB := deriveMemoryBudget()
	applyMemoryCeiling(gwMB)
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	log.Printf("[Runtime] Resource limits configured: Gateway=%dMiB, Worker=%dMiB (GOGC=100) | GOMAXPROCS=%d",
		gwMB, workerMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("PORT", defaultPort)
	renderDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("RENDER_REGION", getEnv("REGION", "")))
	region := normalizeRegion(rawRegion)

	sup := NewSupervisor()
	if err := sup.PreflightContext(sigCtx); err != nil {
		log.Printf("[Gateway] Notice: Preflight check: %v", err)
	}

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if renderDomain != "" {
			cf.SetRenderOrigin(renderDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	}

	rnToken := sanitizeRenderToken(getEnv("RENDER_API_KEY", getEnv("RENDER_API_TOKEN", getEnv("BERMUDA_RENDER_TOKEN", ""))))
	var rn *RenderClient
	if rnToken != "" {
		rn = NewRenderClient(rnToken)
		if renderDomain != "" {
			rn.SetServiceDomain(renderDomain)
		}
		if customDomain != "" {
			rn.SetCustomDomain(customDomain)
		}
	}

	sup.SetInfrastructureDomains(renderDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = renderDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: RenderDomain=%q | CloudflareDomain=%q | Region=%q",
		renderDomain, customDomain, region)

	gw := NewGateway(sup, cf, renderDomain, customDomain, region)
	gw.SetRenderClient(rn)

	topologyUpdater := func(rnDom, cfDom string) {
		sup.SetInfrastructureDomains(rnDom, cfDom, region)
		gw.SetInfrastructureDomains(rnDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if rn != nil {
		rn.SetTopologyCallback(topologyUpdater)
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000); e != nil {
					controlErr = e
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	ln, err := listenCfg.Listen(context.Background(), "tcp", srv.Addr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind listener on %s: %v", srv.Addr, err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("[Gateway] HTTP listener active on :%s (PID %d, GOMAXPROCS=%d)", port, os.Getpid(), procs)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if rn != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, rn, cf, renderDomain, customDomain, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating shutdown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] Shutdown complete. Exit 0.")
}
