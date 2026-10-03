package node

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const xuiWarpMarker = "/etc/wdtt-panel/xui-warp.json"
const xuiWarpTag = "wdtt-panel-warp"

type warpMarker struct {
	InboundTag string `json:"inbound_tag"`
}

func (a *xuiAPI) form(ctx context.Context, path string, values url.Values) (xuiReply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, strings.NewReader(values.Encode()))
	if err != nil {
		return xuiReply{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return xuiReply{}, errors.New("local 3x-ui API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return xuiReply{}, fmt.Errorf("3x-ui API returned HTTP %d", resp.StatusCode)
	}
	var reply xuiReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&reply); err != nil {
		return reply, errors.New("invalid 3x-ui API response")
	}
	if !reply.Success {
		return reply, errors.New("3x-ui API rejected operation")
	}
	return reply, nil
}

func decodeXUIObject(raw json.RawMessage, target any) error {
	if len(raw) > 0 && raw[0] == '"' {
		var inner string
		if err := json.Unmarshal(raw, &inner); err != nil {
			return err
		}
		return json.Unmarshal([]byte(inner), target)
	}
	return json.Unmarshal(raw, target)
}

func (a *xuiAPI) xrayTemplate(ctx context.Context) (map[string]any, string, error) {
	reply, err := a.form(ctx, "/panel/api/xray/", url.Values{})
	if err != nil {
		return nil, "", err
	}
	var wrapper struct {
		XraySetting     json.RawMessage `json:"xraySetting"`
		OutboundTestURL string          `json:"outboundTestUrl"`
	}
	if err := decodeXUIObject(reply.Obj, &wrapper); err != nil {
		return nil, "", errors.New("invalid 3x-ui Xray settings")
	}
	var cfg map[string]any
	if err := decodeXUIObject(wrapper.XraySetting, &cfg); err != nil || cfg == nil {
		return nil, "", errors.New("invalid 3x-ui Xray template")
	}
	return cfg, wrapper.OutboundTestURL, nil
}

func (a *xuiAPI) saveXrayTemplate(ctx context.Context, cfg map[string]any, testURL string) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	values := url.Values{"xraySetting": {string(b)}}
	if testURL != "" {
		values.Set("outboundTestUrl", testURL)
	}
	_, err = a.form(ctx, "/panel/api/xray/update", values)
	return err
}

func (a *xuiAPI) warpRegistration(ctx context.Context) (map[string]string, map[string]any, error) {
	var data map[string]string
	dataReply, dataErr := a.form(ctx, "/panel/api/xray/warp/data", url.Values{})
	if dataErr == nil && decodeXUIObject(dataReply.Obj, &data) == nil && data["private_key"] != "" {
		configReply, err := a.form(ctx, "/panel/api/xray/warp/config", url.Values{})
		if err != nil {
			return nil, nil, err
		}
		var config map[string]any
		if err := decodeXUIObject(configReply.Obj, &config); err != nil {
			return nil, nil, errors.New("invalid WARP configuration")
		}
		return data, config, nil
	}
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return nil, nil, err
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	values := url.Values{"privateKey": {base64.StdEncoding.EncodeToString(private)}, "publicKey": {base64.StdEncoding.EncodeToString(public)}}
	reply, err := a.form(ctx, "/panel/api/xray/warp/reg", values)
	if err != nil {
		return nil, nil, err
	}
	var registered struct {
		Data   map[string]string `json:"data"`
		Config map[string]any    `json:"config"`
	}
	if err := decodeXUIObject(reply.Obj, &registered); err != nil || registered.Data["private_key"] == "" {
		return nil, nil, errors.New("invalid WARP registration")
	}
	return registered.Data, registered.Config, nil
}

func makeWarpOutbound(data map[string]string, registration map[string]any) (map[string]any, error) {
	config, ok := registration["config"].(map[string]any)
	if !ok {
		return nil, errors.New("WARP response has no network configuration")
	}
	iface, ok := config["interface"].(map[string]any)
	if !ok {
		return nil, errors.New("WARP response has no interface")
	}
	addresses, ok := iface["addresses"].(map[string]any)
	if !ok {
		return nil, errors.New("WARP response has no addresses")
	}
	peers, ok := config["peers"].([]any)
	if !ok || len(peers) == 0 {
		return nil, errors.New("WARP response has no peer")
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return nil, errors.New("invalid WARP peer")
	}
	endpoint, ok := peer["endpoint"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid WARP endpoint")
	}
	publicKey, _ := peer["public_key"].(string)
	host, _ := endpoint["host"].(string)
	v4, _ := addresses["v4"].(string)
	if data["private_key"] == "" || publicKey == "" || host == "" || v4 == "" {
		return nil, errors.New("incomplete WARP configuration")
	}
	addressList := []string{v4 + "/32"}
	if v6, _ := addresses["v6"].(string); v6 != "" {
		addressList = append(addressList, v6+"/128")
	}
	settings := map[string]any{
		"secretKey": data["private_key"], "address": addressList, "mtu": 1280,
		"noKernelTun": true,
		"peers":       []any{map[string]any{"publicKey": publicKey, "endpoint": host, "allowedIPs": []string{"0.0.0.0/0", "::/0"}, "keepAlive": 25}},
	}
	clientID, _ := config["client_id"].(string)
	if clientID == "" {
		clientID = data["client_id"]
	}
	if clientID != "" {
		reserved, err := base64.StdEncoding.DecodeString(clientID)
		if err != nil || len(reserved) != 3 {
			return nil, errors.New("invalid WARP reserved bytes")
		}
		settings["reserved"] = []int{int(reserved[0]), int(reserved[1]), int(reserved[2])}
	}
	return map[string]any{"tag": xuiWarpTag, "protocol": "wireguard", "settings": settings}, nil
}

func resolveWarpEndpointIPv4(ctx context.Context, outbound map[string]any) error {
	settings := outbound["settings"].(map[string]any)
	peer := settings["peers"].([]any)[0].(map[string]any)
	endpoint := peer["endpoint"].(string)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return errors.New("invalid WARP endpoint address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return errors.New("WARP endpoint has no IPv4 address")
		}
		return nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return errors.New("could not resolve WARP endpoint")
	}
	for _, address := range addresses {
		if ip := address.IP.To4(); ip != nil {
			peer["endpoint"] = net.JoinHostPort(ip.String(), port)
			return nil
		}
	}
	return errors.New("WARP endpoint has no IPv4 address")
}

func waitWarpRoute(ctx context.Context, inboundTag string, enabled bool) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		if warpRouteLoaded(inboundTag) == enabled {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("3x-ui did not load WARP routing")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func EnableXUIWarp(ctx context.Context) (Result, error) {
	if _, err := os.Stat(xuiWarpMarker); err == nil {
		return Result{Message: "3x-ui WARP is already panel-managed"}, nil
	}
	vless, err := readVLESS()
	if err != nil {
		return Result{}, errors.New("private 3x-ui VLESS inbound is required")
	}
	api, err := localXUI(ctx)
	if err != nil {
		return Result{}, err
	}
	inbounds, err := api.inbounds(ctx)
	if err != nil {
		return Result{}, err
	}
	inboundTag := ""
	for _, in := range inbounds {
		if in.ID == vless.InboundID && xuiInboundMatches(in, vless) && in.Enable {
			inboundTag = in.Tag
			break
		}
	}
	if inboundTag == "" {
		return Result{}, errors.New("panel-owned VLESS inbound is unavailable")
	}
	config, testURL, err := api.xrayTemplate(ctx)
	if err != nil {
		return Result{}, err
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok {
		return Result{}, errors.New("3x-ui outbound list is invalid")
	}
	for _, item := range outbounds {
		if ob, ok := item.(map[string]any); ok && ob["tag"] == xuiWarpTag {
			return Result{}, errors.New("WARP tag already exists outside panel ownership")
		}
	}
	data, registration, err := api.warpRegistration(ctx)
	if err != nil {
		return Result{}, err
	}
	outbound, err := makeWarpOutbound(data, registration)
	if err != nil {
		return Result{}, err
	}
	if err := resolveWarpEndpointIPv4(ctx, outbound); err != nil {
		return Result{}, err
	}
	outboundJSON, _ := json.Marshal(outbound)
	if _, err := api.form(ctx, "/panel/api/xray/testOutbound", url.Values{"outbound": {string(outboundJSON)}, "mode": {"real"}}); err != nil {
		return Result{}, errors.New("WARP outbound connectivity test failed")
	}
	routing, ok := config["routing"].(map[string]any)
	if !ok {
		return Result{}, errors.New("3x-ui routing is invalid")
	}
	rules, ok := routing["rules"].([]any)
	if !ok {
		return Result{}, errors.New("3x-ui routing rules are invalid")
	}
	for _, item := range rules {
		if rule, ok := item.(map[string]any); ok && rule["outboundTag"] == xuiWarpTag {
			return Result{}, errors.New("WARP rule already exists outside panel ownership")
		}
	}
	previous, _ := json.Marshal(config)
	config["outbounds"] = append(outbounds, outbound)
	rule := map[string]any{"type": "field", "inboundTag": []string{inboundTag}, "outboundTag": xuiWarpTag, "network": "tcp,udp"}
	if len(rules) > 0 {
		routing["rules"] = append([]any{rules[0], rule}, rules[1:]...)
	} else {
		routing["rules"] = []any{rule}
	}
	if err := api.saveXrayTemplate(ctx, config, testURL); err != nil {
		var restore map[string]any
		if json.Unmarshal(previous, &restore) == nil {
			_ = api.saveXrayTemplate(ctx, restore, testURL)
		}
		return Result{}, err
	}
	if err := run(ctx, "systemctl", "restart", "x-ui.service"); err != nil {
		var restore map[string]any
		if json.Unmarshal(previous, &restore) == nil {
			_ = api.saveXrayTemplate(ctx, restore, testURL)
			_ = run(ctx, "systemctl", "restart", "x-ui.service")
		}
		return Result{}, err
	}
	if err := waitWarpRoute(ctx, inboundTag, true); err != nil {
		var restore map[string]any
		if json.Unmarshal(previous, &restore) == nil {
			_ = api.saveXrayTemplate(ctx, restore, testURL)
			_ = run(ctx, "systemctl", "restart", "x-ui.service")
		}
		return Result{}, err
	}
	markerData, _ := json.Marshal(warpMarker{InboundTag: inboundTag})
	if err := os.WriteFile(xuiWarpMarker, markerData, 0600); err != nil {
		return Result{}, err
	}
	return Result{Message: "3x-ui WARP enabled for the private VLESS inbound"}, nil
}

func DisableXUIWarp(ctx context.Context) (Result, error) {
	b, err := os.ReadFile(xuiWarpMarker)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Message: "Panel-managed 3x-ui WARP is already disabled"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	var marker warpMarker
	if err := json.Unmarshal(b, &marker); err != nil || marker.InboundTag == "" {
		return Result{}, errors.New("invalid WARP ownership marker")
	}
	api, err := localXUI(ctx)
	if err != nil {
		return Result{}, err
	}
	config, testURL, err := api.xrayTemplate(ctx)
	if err != nil {
		return Result{}, err
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok {
		return Result{}, errors.New("3x-ui outbound list is invalid")
	}
	keptOutbounds := make([]any, 0, len(outbounds))
	for _, item := range outbounds {
		if ob, ok := item.(map[string]any); ok && ob["tag"] == xuiWarpTag {
			continue
		}
		keptOutbounds = append(keptOutbounds, item)
	}
	config["outbounds"] = keptOutbounds
	routing, ok := config["routing"].(map[string]any)
	if !ok {
		return Result{}, errors.New("3x-ui routing is invalid")
	}
	rules, ok := routing["rules"].([]any)
	if !ok {
		return Result{}, errors.New("3x-ui routing rules are invalid")
	}
	keptRules := make([]any, 0, len(rules))
	for _, item := range rules {
		if rule, ok := item.(map[string]any); ok && rule["outboundTag"] == xuiWarpTag {
			continue
		}
		keptRules = append(keptRules, item)
	}
	routing["rules"] = keptRules
	if err := api.saveXrayTemplate(ctx, config, testURL); err != nil {
		return Result{}, err
	}
	if err := run(ctx, "systemctl", "restart", "x-ui.service"); err != nil {
		return Result{}, err
	}
	if err := waitWarpRoute(ctx, marker.InboundTag, false); err != nil {
		return Result{}, err
	}
	if err := os.Remove(xuiWarpMarker); err != nil {
		return Result{}, err
	}
	return Result{Message: "3x-ui WARP disabled; private VLESS returns to direct outbound"}, nil
}

func warpRouteLoaded(inboundTag string) bool {
	b, err := os.ReadFile("/usr/local/x-ui/bin/config.json")
	if err != nil {
		return false
	}
	var config struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(b, &config) != nil {
		return false
	}
	readyOutbound := false
	readyRule := false
	for _, outbound := range config.Outbounds {
		if outbound.Tag == xuiWarpTag {
			readyOutbound = true
		}
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag == xuiWarpTag {
			for _, tag := range rule.InboundTag {
				if tag == inboundTag {
					readyRule = true
				}
			}
		}
	}
	return readyOutbound && readyRule
}
