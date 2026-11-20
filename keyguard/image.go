package keyguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxImageResponse = 64 << 20

func checkImageRequest(provider string, body []byte) (string, int, []byte, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return "", 0, nil, errors.New("нужен JSON объект")
	}
	allowed := map[string]bool{"model": true, "prompt": true, "input": true, "n": true, "size": true, "quality": true, "output_format": true}
	for k := range fields {
		if !allowed[k] {
			return "", 0, nil, fmt.Errorf("поле изображения %q не разрешено", k)
		}
	}
	if provider == "openai" {
		var req struct {
			Model        string `json:"model"`
			Prompt       string `json:"prompt"`
			N            int    `json:"n"`
			Size         string `json:"size"`
			Quality      string `json:"quality"`
			OutputFormat string `json:"output_format"`
		}
		if json.Unmarshal(body, &req) != nil || len(req.Prompt) == 0 || len(req.Prompt) > 16000 || req.N < 1 || req.N > 4 {
			return "", 0, nil, errors.New("нужны prompt и n от 1 до 4")
		}
		if req.Size != "1024x1024" && req.Size != "1536x1024" && req.Size != "1024x1536" {
			return "", 0, nil, errors.New("size должен быть 1024x1024, 1536x1024 или 1024x1536")
		}
		if req.Quality != "low" && req.Quality != "medium" && req.Quality != "high" {
			return "", 0, nil, errors.New("quality должен быть low, medium или high")
		}
		if req.OutputFormat != "png" && req.OutputFormat != "jpeg" && req.OutputFormat != "webp" {
			return "", 0, nil, errors.New("output_format должен быть png, jpeg или webp")
		}
		return req.Model, req.N, body, nil
	}
	var req struct {
		Model string `json:"model"`
		Input []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"input"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Input) != 1 || req.Input[0].Type != "text" || len(req.Input[0].Text) == 0 || len(req.Input[0].Text) > 16000 {
		return "", 0, nil, errors.New("нужен один текстовый input")
	}
	return req.Model, 1, body, nil
}

func (s *Server) handleImageGenerate(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			fail(w, 400, "нужен POST без query")
			return
		}
		c, err := s.caller(r)
		if err != nil {
			fail(w, 401, "не опознан")
			return
		}
		p := s.Providers[provider]
		if p == nil {
			fail(w, 404, "провайдер не настроен")
			return
		}
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		model, count, body, err := checkImageRequest(provider, body)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		rate, allowed := p.ImagePerImage[model]
		if !allowed || rate <= 0 {
			fail(w, 400, "модель генерации изображений не разрешена")
			return
		}
		user, budgets, ok := s.mediaPayerFor(w, r, c, provider, model, "генерацию изображений")
		if !ok {
			return
		}
		reserve := rate * float64(count)
		res, err := s.Ledger.Reserve(budgets, reserve)
		if errors.Is(err, ErrState) {
			s.stateFail(w, "image.reserve", err)
			return
		}
		if err != nil {
			fail(w, 402, err.Error())
			return
		}
		key, err := s.Store.Get(r.Context(), user, provider)
		if err != nil {
			res.Settle(0, true)
			fail(w, 409, "ключ не задан")
			return
		}
		if provider == "openai" {
			var fields map[string]any
			json.Unmarshal(body, &fields)
			fields["safety_identifier"] = uid(user)
			body, _ = json.Marshal(fields)
		}
		upstream := p.BaseURL + "/v1/images/generations"
		if provider == "google" {
			upstream = p.BaseURL + "/v1beta/interactions"
		}
		req, _ := http.NewRequestWithContext(r.Context(), "POST", upstream, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if provider == "google" {
			req.Header.Set("x-goog-api-key", key)
			req.Header.Set("Api-Revision", "2026-05-20")
		} else {
			setAuth(req, p, key)
		}
		resp, err := s.providerHTTP(p).Do(req)
		if err != nil {
			res.Settle(0, true)
			fail(w, 502, "провайдер недоступен")
			return
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(io.LimitReader(resp.Body, maxImageResponse))
		if err != nil {
			res.Settle(0, true)
			fail(w, 502, "ответ провайдера оборвался")
			return
		}
		charged := 0.0
		if resp.StatusCode >= 400 {
			res.Settle(0, true)
		} else {
			actual, known := reserve, true
			if provider == "openai" {
				var result struct {
					Usage struct {
						InputTokens  int64 `json:"input_tokens"`
						OutputTokens int64 `json:"output_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal(out, &result) == nil && result.Usage.OutputTokens > 0 {
					actual = float64(result.Usage.InputTokens)*5/1e6 + float64(result.Usage.OutputTokens)*30/1e6
				}
			}
			charged = res.Settle(actual, known)
		}
		out = bytes.ReplaceAll(out, []byte(key), []byte("[redacted]"))
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		w.Write(out)
		s.Log.Printf("event=media.image ns=%s payer=%s provider=%s model=%s count=%d status=%d charged_usd=%.6f",
			logNS(c.Namespace), uid(user), provider, model, count, resp.StatusCode, charged)
	}
}
