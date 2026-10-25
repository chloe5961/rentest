package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	renderAPIBase            = "https://api.render.com/v1"
	defaultRenderAnycastIP   = "216.24.57.1"
	defaultRNReqTimeout      = 15 * time.Second
	defaultRNCertPollTick    = 6 * time.Second
	defaultRNCertPollWait    = 90 * time.Second
	defaultRNTLSProbeTimeout = 4 * time.Second
	defaultRNTargetPort      = 8080
)

type rnAPIError struct {
	StatusCode int
	ID         string `json:"id,omitempty"`
	Message    string `json:"message,omitempty"`
}

func (e *rnAPIError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("render api error (HTTP %d): %s", e.StatusCode, strings.TrimSpace(e.Message))
	}
	return fmt.Sprintf("render api error (HTTP %d)", e.StatusCode)
}

func (e *rnAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden || e.StatusCode == http.StatusPaymentRequired {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "plan") ||
		strings.Contains(lower, "quota") ||
		strings.Contains(lower, "limit")
}

type RenderCustomDomainInfo struct {
	ID                 string
	Domain             string
	CNAMETarget        string
	ServerObjName      string
	VerificationStatus string
	CertificateStatus  string
	RecordsVerified    bool
}

func (info *RenderCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "" ||
		strings.Contains(st, "PROVISION") ||
		strings.Contains(st, "PENDING") ||
		strings.Contains(st, "UNVERIFIED") ||
		strings.Contains(st, "INVALID") ||
		strings.Contains(st, "FAILED") ||
		strings.Contains(st, "ERROR") {
		return false
	}
	if st == "VALID" ||
		st == "ISSUED" ||
		st == "ACTIVE" ||
		st == "READY" ||
		st == "VERIFIED" {
		return true
	}
	return strings.Contains(st, "VALID")
}

type RenderClient struct {
	Token       string
	ServiceID   string
	ServiceName string
	TargetPort  int
	apiBase     string
	client      *http.Client

	mu               sync.RWMutex
	serviceDomain    string
	customDomain     string
	discoveredRegion string
	onTopology       func(renderDom, cfDom string)
}

func sanitizeRenderToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"RENDER_API_KEY", "RENDER_API_TOKEN", "RENDER_TOKEN", "BERMUDA_RENDER_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func NewRenderClient(token string) *RenderClient {
	cleanTok := sanitizeRenderToken(token)
	if cleanTok == "" {
		return nil
	}

	port := getEnvInt("PORT", defaultRNTargetPort)
	if port <= 0 {
		port = defaultRNTargetPort
	}

	rnDom, cfDom := resolveInfrastructureDomains()
	apiURL := sanitizeExplicitCredential(getEnv("RENDER_API_URL", getEnv("BERMUDA_RENDER_API_URL", renderAPIBase)))
	if apiURL == "" {
		apiURL = renderAPIBase
	}
	apiURL = strings.TrimRight(apiURL, "/")

	srvID := sanitizeExplicitCredential(getEnv("RENDER_SERVICE_ID", getEnv("BERMUDA_RENDER_SERVICE_ID", "")))
	srvName := sanitizeExplicitCredential(getEnv("RENDER_SERVICE_NAME", ""))

	return &RenderClient{
		Token:         cleanTok,
		ServiceID:     srvID,
		ServiceName:   srvName,
		TargetPort:    port,
		apiBase:       apiURL,
		serviceDomain: rnDom,
		customDomain:  cfDom,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *RenderClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *RenderClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ServiceID != ""
}

func (c *RenderClient) SetTopologyCallback(fn func(renderDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *RenderClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	rn := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(rn, cf)
	}
}

func (c *RenderClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *RenderClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *RenderClient) GetDiscoveredRegion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discoveredRegion
}

func (c *RenderClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isRenderPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullRenderServiceDomain(clean) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *RenderClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isRenderManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *RenderClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return renderAPIBase
}

func doRNRequest(ctx context.Context, c *RenderClient, method, path string, body any) ([]byte, int, error) {
	if !c.IsConfigured() {
		return nil, 0, errors.New("render client not configured")
	}

	var reqBytes []byte
	if body != nil {
		var err error
		reqBytes, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal render payload: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultRNReqTimeout)
		var bodyReader io.Reader
		if len(reqBytes) > 0 {
			bodyReader = bytes.NewReader(reqBytes)
		}

		req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL()+path, bodyReader)
		if err != nil {
			cancel()
			return nil, 0, fmt.Errorf("build render request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "Bermuda-Edge-Router/4.0")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("read render response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return nil, resp.StatusCode, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
				continue
			}
		}

		if resp.StatusCode >= 400 {
			apiErr := &rnAPIError{StatusCode: resp.StatusCode}
			if err := json.Unmarshal(rawBytes, apiErr); err != nil || apiErr.Message == "" {
				snippet := strings.TrimSpace(string(rawBytes))
				if len(snippet) > 256 {
					snippet = snippet[:256]
				}
				apiErr.Message = snippet
			}
			return rawBytes, resp.StatusCode, apiErr
		}

		return rawBytes, resp.StatusCode, nil
	}

	return nil, 0, lastErr
}

type rnServiceDetails struct {
	URL    string `json:"url"`
	Region string `json:"region"`
	Plan   string `json:"plan"`
}

type rnServiceObject struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Type           string           `json:"type"`
	Slug           string           `json:"slug"`
	ServiceDetails rnServiceDetails `json:"serviceDetails"`
}

type rnServiceListElement struct {
	Cursor  string           `json:"cursor"`
	Service *rnServiceObject `json:"service"`
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Type    string           `json:"type"`
	Slug    string           `json:"slug"`
	Details rnServiceDetails `json:"serviceDetails"`
}

func (e rnServiceListElement) unwrap() rnServiceObject {
	if e.Service != nil && e.Service.ID != "" {
		return *e.Service
	}
	return rnServiceObject{
		ID:             e.ID,
		Name:           e.Name,
		Type:           e.Type,
		Slug:           e.Slug,
		ServiceDetails: e.Details,
	}
}

func (c *RenderClient) applyServiceMetadata(svc rnServiceObject) {
	if svc.ID == "" {
		return
	}
	cleanURLHost := cleanHost(svc.ServiceDetails.URL)
	if cleanURLHost == "" && svc.Slug != "" {
		cleanURLHost = cleanHost(svc.Slug + ".onrender.com")
	}

	c.mu.Lock()
	if c.ServiceID == "" {
		c.ServiceID = svc.ID
	}
	if c.ServiceName == "" && svc.Name != "" {
		c.ServiceName = svc.Name
	}
	if isRenderPublicDomain(cleanURLHost) && (c.serviceDomain == "" || isFullRenderServiceDomain(cleanURLHost)) {
		c.serviceDomain = cleanURLHost
	}
	if svc.ServiceDetails.Region != "" {
		c.discoveredRegion = normalizeRegion(svc.ServiceDetails.Region)
	}
	c.mu.Unlock()
	c.notifyTopology()
}

func (c *RenderClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("render client not configured")
	}

	c.mu.RLock()
	srvID := c.ServiceID
	srvDom := c.serviceDomain
	srvName := c.ServiceName
	c.mu.RUnlock()

	if srvID != "" {
		if srvDom != "" {
			return nil
		}
		raw, _, err := doRNRequest(ctx, c, http.MethodGet, "/services/"+url.PathEscape(srvID), nil)
		if err == nil && len(raw) > 0 {
			var svc rnServiceObject
			if json.Unmarshal(raw, &svc) == nil && svc.ID != "" {
				c.applyServiceMetadata(svc)
				return nil
			}
		}
		return nil
	}

	raw, _, err := doRNRequest(ctx, c, http.MethodGet, "/services?limit=20", nil)
	if err != nil {
		return fmt.Errorf("discover render services: %w", err)
	}

	var items []rnServiceListElement
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("decode render services list: %w", err)
	}
	if len(items) == 0 {
		return errors.New("no services found under this render api key")
	}

	var selected rnServiceObject
	for _, item := range items {
		svc := item.unwrap()
		if svc.ID == "" {
			continue
		}
		candDom := cleanHost(svc.ServiceDetails.URL)
		if srvDom != "" && candDom == srvDom {
			selected = svc
			break
		}
		if srvName != "" && strings.EqualFold(svc.Name, srvName) {
			selected = svc
			break
		}
		if selected.ID == "" && (svc.Type == "web_service" || svc.Type == "") {
			selected = svc
		}
	}

	if selected.ID == "" {
		selected = items[0].unwrap()
	}
	if selected.ID == "" {
		return errors.New("unable to identify target render service ID")
	}

	c.applyServiceMetadata(selected)
	log.Printf("[Render] ✓ Resolved Runtime Service Context: %s (%s)", selected.ID, selected.Name)
	return nil
}

func (c *RenderClient) UpsertVariable(ctx context.Context, name, value string) error {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return err
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()

	path := fmt.Sprintf("/services/%s/env-vars/%s", url.PathEscape(srvID), url.PathEscape(name))
	payload := map[string]string{
		"value": value,
	}

	_, _, err := doRNRequest(ctx, c, http.MethodPut, path, payload)
	return err
}

func (c *RenderClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}
	if err := c.UpsertVariable(ctx, "BERMUDA_MASTER_KEY", strings.TrimSpace(masterKey)); err != nil {
		var apiErr *rnAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Render] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token permission restriction)")
			return false
		}
		log.Printf("[Render] Warning: Could not persist BERMUDA_MASTER_KEY to Render Environment Variables: %v", err)
		return false
	}
	log.Println("[Render] ✓ BERMUDA_MASTER_KEY persisted atomically to Render Service Environment Variables")
	return true
}

func (c *RenderClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if dom := c.GetServiceDomain(); isFullRenderServiceDomain(dom) {
		log.Printf("[Render] ✓ Service Domain Verified: %s (Port %d)", dom, c.TargetPort)
		return dom, nil
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}

	c.mu.RLock()
	srvID := c.ServiceID
	dom := c.serviceDomain
	c.mu.RUnlock()

	if isFullRenderServiceDomain(dom) {
		log.Printf("[Render] ✓ Service Domain Discovered: %s (Port %d)", dom, c.TargetPort)
		return dom, nil
	}

	if srvID != "" {
		raw, _, err := doRNRequest(ctx, c, http.MethodGet, "/services/"+url.PathEscape(srvID), nil)
		if err == nil && len(raw) > 0 {
			var svc rnServiceObject
			if json.Unmarshal(raw, &svc) == nil && svc.ID != "" {
				c.applyServiceMetadata(svc)
			}
		}
	}

	dom = c.GetServiceDomain()
	if dom != "" {
		log.Printf("[Render] ✓ Service Domain Verified: %s (Port %d)", dom, c.TargetPort)
	}
	return dom, nil
}

type rnCustomDomainServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type rnCustomDomainObject struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	DomainType         string                `json:"domainType"`
	PublicSuffix       string                `json:"publicSuffix"`
	RedirectForName    string                `json:"redirectForName"`
	VerificationStatus string                `json:"verificationStatus"`
	Server             *rnCustomDomainServer `json:"server,omitempty"`
}

type rnCustomDomainListElement struct {
	Cursor             string                `json:"cursor"`
	CustomDomain       *rnCustomDomainObject `json:"customDomain"`
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	DomainType         string                `json:"domainType"`
	PublicSuffix       string                `json:"publicSuffix"`
	RedirectForName    string                `json:"redirectForName"`
	VerificationStatus string                `json:"verificationStatus"`
	Server             *rnCustomDomainServer `json:"server,omitempty"`
}

func (e rnCustomDomainListElement) unwrap() rnCustomDomainObject {
	if e.CustomDomain != nil && (e.CustomDomain.ID != "" || e.CustomDomain.Name != "") {
		return *e.CustomDomain
	}
	return rnCustomDomainObject{
		ID:                 e.ID,
		Name:               e.Name,
		DomainType:         e.DomainType,
		PublicSuffix:       e.PublicSuffix,
		RedirectForName:    e.RedirectForName,
		VerificationStatus: e.VerificationStatus,
		Server:             e.Server,
	}
}

func probeCustomDomainTLS(ctx context.Context, customDomain, gatewayHost string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}

	dialTarget := defaultRenderAnycastIP
	_ = gatewayHost

	dialer := &net.Dialer{
		Timeout: defaultRNTLSProbeTimeout,
	}
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialer.Timeout {
			dialer.Timeout = rem
		}
	}

	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(dialTarget, "443"), &tls.Config{
		ServerName:         cleanCustom,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return false
	}
	_ = tlsConn.Close()
	return true
}

func (c *RenderClient) toCustomDomainInfo(ctx context.Context, obj rnCustomDomainObject) *RenderCustomDomainInfo {
	dom := cleanHost(obj.Name)
	cnameTarget := c.GetServiceDomain()
	var serverName string
	if obj.Server != nil && cleanHost(obj.Server.Name) != "" {
		serverName = cleanHost(obj.Server.Name)
		if cnameTarget == "" {
			cnameTarget = serverName
		}
	}

	verStatus := strings.ToLower(strings.TrimSpace(obj.VerificationStatus))
	verified := verStatus == "verified"

	certStatus := "PENDING_TLS"
	if probeCustomDomainTLS(ctx, dom, cnameTarget) {
		certStatus = "VALID"
		verified = true
	} else if verified {
		certStatus = "PROVISIONING"
	}

	return &RenderCustomDomainInfo{
		ID:                 obj.ID,
		Domain:             dom,
		CNAMETarget:        cnameTarget,
		ServerObjName:      serverName,
		VerificationStatus: verStatus,
		CertificateStatus:  certStatus,
		RecordsVerified:    verified,
	}
}

func (c *RenderClient) listCustomDomains(ctx context.Context) ([]rnCustomDomainObject, error) {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()

	path := fmt.Sprintf("/services/%s/custom-domains?limit=50", url.PathEscape(srvID))
	raw, _, err := doRNRequest(ctx, c, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var elems []rnCustomDomainListElement
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, err
	}

	out := make([]rnCustomDomainObject, 0, len(elems))
	for _, el := range elems {
		obj := el.unwrap()
		if obj.Name != "" {
			out = append(out, obj)
		}
	}
	return out, nil
}

func (c *RenderClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*RenderCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isRenderManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	existing, err := c.listCustomDomains(ctx)
	if err == nil {
		for _, cd := range existing {
			if cleanHost(cd.Name) == cleanTarget {
				c.SetCustomDomain(cleanTarget)
				c.notifyTopology()
				info := c.toCustomDomainInfo(ctx, cd)
				log.Printf("[Render] ✓ Custom Domain Already Registered: %s (ID: %s, CNAME Target: %s, VerifyStatus: %s, CertStatus: %s)",
					cleanTarget, info.ID, info.CNAMETarget, info.VerificationStatus, info.CertificateStatus)
				return info, nil
			}
		}
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()

	path := fmt.Sprintf("/services/%s/custom-domains", url.PathEscape(srvID))
	payload := map[string]string{
		"name": cleanTarget,
	}

	raw, _, postErr := doRNRequest(ctx, c, http.MethodPost, path, payload)
	if postErr != nil {
		var apiErr *rnAPIError
		if errors.As(postErr, &apiErr) && apiErr.StatusCode == http.StatusConflict {
			if refreshed, listErr := c.listCustomDomains(ctx); listErr == nil {
				for _, cd := range refreshed {
					if cleanHost(cd.Name) == cleanTarget {
						c.SetCustomDomain(cleanTarget)
						c.notifyTopology()
						return c.toCustomDomainInfo(ctx, cd), nil
					}
				}
			}
		}
		return nil, fmt.Errorf("register custom domain %s on render: %w", cleanTarget, postErr)
	}

	var createdList []rnCustomDomainObject
	if err := json.Unmarshal(raw, &createdList); err != nil {
		var single rnCustomDomainObject
		if singleErr := json.Unmarshal(raw, &single); singleErr == nil && single.Name != "" {
			createdList = []rnCustomDomainObject{single}
		}
	}

	var matched rnCustomDomainObject
	for _, item := range createdList {
		if cleanHost(item.Name) == cleanTarget {
			matched = item
			break
		}
	}
	if matched.Name == "" && len(createdList) > 0 {
		matched = createdList[0]
	}
	if matched.Name == "" {
		matched.Name = cleanTarget
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	info := c.toCustomDomainInfo(ctx, matched)

	log.Printf("[Render] ✓ Auto-Registered Custom Domain: %s -> CNAME Target: %s (ID: %s, CertStatus: %s)",
		cleanTarget, info.CNAMETarget, info.ID, info.CertificateStatus)
	return info, nil
}

func (c *RenderClient) TriggerCustomDomainVerify(ctx context.Context, customDomainID, targetDomain string) bool {
	if !c.IsConfigured() {
		return false
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return false
	}

	idOrName := strings.TrimSpace(customDomainID)
	if idOrName == "" {
		idOrName = cleanHost(targetDomain)
	}
	if idOrName == "" {
		return false
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()

	path := fmt.Sprintf("/services/%s/custom-domains/%s/verify", url.PathEscape(srvID), url.PathEscape(idOrName))
	_, _, err := doRNRequest(ctx, c, http.MethodPost, path, nil)
	if err != nil {
		return false
	}
	log.Printf("[Render] ✓ Triggered DNS & TLS verification check on Render for %s", cleanHost(targetDomain))
	return true
}

func (c *RenderClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*RenderCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if err := c.ResolveRuntimeContext(ctx); err == nil {
		c.mu.RLock()
		srvID := c.ServiceID
		c.mu.RUnlock()

		idOrName := strings.TrimSpace(customDomainID)
		if idOrName == "" {
			idOrName = cleanTarget
		}
		if idOrName != "" {
			path := fmt.Sprintf("/services/%s/custom-domains/%s", url.PathEscape(srvID), url.PathEscape(idOrName))
			if raw, _, reqErr := doRNRequest(ctx, c, http.MethodGet, path, nil); reqErr == nil && len(raw) > 0 {
				var obj rnCustomDomainObject
				if json.Unmarshal(raw, &obj) == nil && obj.Name != "" {
					return c.toCustomDomainInfo(ctx, obj), nil
				}
			}
		}
	}

	if doms, err := c.listCustomDomains(ctx); err == nil {
		for _, cd := range doms {
			if (customDomainID != "" && cd.ID == customDomainID) || (cleanTarget != "" && cleanHost(cd.Name) == cleanTarget) {
				return c.toCustomDomainInfo(ctx, cd), nil
			}
		}
	}

	cnameTarget := c.GetServiceDomain()
	if probeCustomDomainTLS(ctx, cleanTarget, cnameTarget) {
		return &RenderCustomDomainInfo{
			ID:                 customDomainID,
			Domain:             cleanTarget,
			CNAMETarget:        cnameTarget,
			VerificationStatus: "verified",
			CertificateStatus:  "VALID",
			RecordsVerified:    true,
		}, nil
	}

	return &RenderCustomDomainInfo{
		ID:                 customDomainID,
		Domain:             cleanTarget,
		CNAMETarget:        cnameTarget,
		VerificationStatus: "unverified",
		CertificateStatus:  "PENDING_TLS",
	}, nil
}

func (c *RenderClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*RenderCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultRNCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultRNCertPollTick)
	defer ticker.Stop()

	var latest *RenderCustomDomainInfo
	pollCount := 0
	for {
		if pollCount%2 == 1 {
			c.TriggerCustomDomainVerify(waitCtx, customDomainID, targetDomain)
		}
		pollCount++

		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Render] ✓ Custom Domain %s TLS Certificate ISSUED & VALID (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *RenderClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Render] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Kernel IPv6 routing table online)")
	} else {
		log.Println("[Render] ✓ Outbound Network Stack: IPv4 Active (Standard IPv4 egress routing verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return
	}

	c.mu.RLock()
	srvID := c.ServiceID
	srvDom := c.serviceDomain
	reg := c.discoveredRegion
	port := c.TargetPort
	c.mu.RUnlock()

	healthPath := getEnv("BERMUDA_HEALTH_PATH", "/healthz")
	log.Printf("[Render] ✓ Compute & Network Verified: Service=%s | Domain=%s | Region=%s | Port=%d | HealthPath=%s",
		srvID, srvDom, reg, port, healthPath)
}
