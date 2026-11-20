package keyguard

// Облачная транскрибация: multipart OpenAI и JSON Gemini. Отдельно от handleLLM: тариф — за минуту,
// тело содержит аудио, а не сообщения чата. Модель и длительность ограничены, ключ подставляется только здесь.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

const maxMediaBody = 64 << 20

func (s *Server) handleMediaTranscribe(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, 405, "POST")
			return
		}
		c, err := s.caller(r)
		if err != nil {
			fail(w, 401, "не опознан")
			return
		}
		p := s.Providers[provider]
		model := r.Header.Get("X-Deck-Model")
		if provider == "openai" {
			model = "" // OpenAI передаёт модель в multipart; читаем её ниже
		}
		seconds, err := strconv.ParseFloat(r.Header.Get("X-Deck-Media-Seconds"), 64)
		if p == nil || err != nil || seconds <= 0 || seconds > 86400 || r.URL.RawQuery != "" {
			fail(w, 400, "нужны модель и положительная длительность до 24 часов")
			return
		}
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		if provider == "openai" {
			model, err = checkTranscribeMultipart(r.Header.Get("Content-Type"), body)
		} else {
			err = checkTranscribeJSON(body)
		}
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		rate, allowed := p.MediaPerMinute[model]
		if !allowed || rate <= 0 {
			fail(w, 400, "модель транскрибации не разрешена")
			return
		}
		user, budgets, ok := s.mediaPayer(w, r, c, provider, model)
		if !ok {
			return
		}
		reserve := seconds / 60 * rate
		res, err := s.Ledger.Reserve(budgets, reserve)
		if errors.Is(err, ErrState) {
			s.stateFail(w, "media.reserve", err)
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
		var upstream string
		var contentType string
		if provider == "openai" {
			upstream = p.BaseURL + "/v1/audio/transcriptions"
			contentType = r.Header.Get("Content-Type")
		} else {
			upstream = p.BaseURL + "/v1beta/models/" + model + ":generateContent"
			contentType = "application/json"
		}
		req, _ := http.NewRequestWithContext(r.Context(), "POST", upstream, bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		if provider == "google" {
			req.Header.Set("x-goog-api-key", key)
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
		out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			res.Settle(0, true)
			fail(w, 502, "ответ провайдера оборвался")
			return
		}
		if resp.StatusCode >= 400 {
			res.Settle(0, true)
		} else {
			res.Settle(reserve, true)
		}
		out = bytes.ReplaceAll(out, []byte(key), []byte("[redacted]"))
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		w.Write(out)
		s.Log.Printf("event=media.transcribe ns=%s payer=%s provider=%s model=%s status=%d seconds=%.0f charged_usd=%.6f",
			logNS(c.Namespace), uid(user), provider, model, resp.StatusCode, seconds, reserve)
	}
}

func (s *Server) mediaPayer(w http.ResponseWriter, r *http.Request, c Caller, provider, model string) (string, []string, bool) {
	return s.mediaPayerFor(w, r, c, provider, model, "транскрибацию")
}

// mediaPayerFor — те же личные лимиты и разрешения спонсора, что у вызовов LLM, для медиа-тарифов.
func (s *Server) mediaPayerFor(w http.ResponseWriter, r *http.Request, c Caller, provider, model, action string) (string, []string, bool) {
	now := s.Now()
	switch {
	case strings.HasPrefix(c.Namespace, "deck-u-"):
		user := strings.TrimPrefix(c.Namespace, "deck-u-")
		if err := s.applyMonthCap(user, now); err != nil {
			s.stateFail(w, "ledger.limit", err)
			return "", nil, false
		}
		return user, []string{"user:" + user, monthKey(user, now)}, true
	case strings.HasPrefix(c.Namespace, "deck-t-"):
		space := strings.TrimPrefix(c.Namespace, "deck-")
		chat, member := r.Header.Get("X-Deck-Chat"), r.Header.Get("X-Deck-Member")
		g, ok := s.Grants.Find(space, chat, provider, model, now)
		if !ok || !contains(g.Members, member) {
			fail(w, 403, "нет разрешения спонсора на "+action+" этой модели")
			return "", nil, false
		}
		budgets := []string{"grant:" + g.ID}
		if g.PerMemberUSDDay > 0 {
			k := fmt.Sprintf("grant:%s:%s:%s", g.ID, member, now.UTC().Format("2006-01-02"))
			if err := s.Ledger.SetLimitOnce(k, g.PerMemberUSDDay); err != nil {
				s.stateFail(w, "ledger.limit", err)
				return "", nil, false
			}
			budgets = append(budgets, k)
		}
		return g.Sponsor, budgets, true
	default:
		fail(w, 403, "только пространства")
		return "", nil, false
	}
}

func checkTranscribeMultipart(contentType string, body []byte) (string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return "", fmt.Errorf("нужен multipart/form-data")
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	model, files := "", 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("повреждённый multipart")
		}
		switch part.FormName() {
		case "file":
			files++
			if _, err := io.Copy(io.Discard, io.LimitReader(part, maxMediaBody+1)); err != nil {
				return "", fmt.Errorf("аудио не прочитано")
			}
		case "model":
			raw, _ := io.ReadAll(io.LimitReader(part, 200))
			model = string(raw)
		case "response_format":
			raw, _ := io.ReadAll(io.LimitReader(part, 100))
			if string(raw) != "diarized_json" {
				return "", fmt.Errorf("response_format не разрешён")
			}
		case "chunking_strategy":
			raw, _ := io.ReadAll(io.LimitReader(part, 100))
			if string(raw) != "auto" {
				return "", fmt.Errorf("chunking_strategy не разрешён")
			}
		default:
			return "", fmt.Errorf("поле %q не разрешено", part.FormName())
		}
	}
	if files != 1 || model == "" {
		return "", fmt.Errorf("нужны один аудиофайл и модель")
	}
	return model, nil
}

func checkTranscribeJSON(body []byte) error {
	req, err := ParseStrict(body, true)
	if err != nil {
		return err
	}
	for k := range req {
		if k != "contents" && k != "generationConfig" {
			return fmt.Errorf("поле %q не разрешено", k)
		}
	}
	contents, ok := req["contents"].([]any)
	if !ok || len(contents) != 1 {
		return fmt.Errorf("нужен один блок contents")
	}
	gc, ok := req["generationConfig"].(map[string]any)
	if !ok {
		return fmt.Errorf("нужен generationConfig")
	}
	expectedSchema := map[string]any{"type": "ARRAY", "items": map[string]any{
		"type": "OBJECT", "properties": map[string]any{
			"start": map[string]any{"type": "NUMBER"}, "end": map[string]any{"type": "NUMBER"},
			"text": map[string]any{"type": "STRING"}, "speaker": map[string]any{"type": "STRING"},
		}, "required": []any{"start", "end", "text"},
	}}
	for k, v := range gc {
		switch k {
		case "responseMimeType":
			if v != "application/json" {
				return fmt.Errorf("generationConfig.responseMimeType не разрешён")
			}
		case "maxOutputTokens":
			number, ok := v.(json.Number)
			tokens, err := strconv.ParseInt(number.String(), 10, 64)
			if !ok || err != nil || tokens < 1 || tokens > 16384 {
				return fmt.Errorf("maxOutputTokens должен быть целым числом от 1 до 16384")
			}
		case "responseSchema":
			if !reflect.DeepEqual(v, expectedSchema) {
				return fmt.Errorf("responseSchema не разрешена")
			}
		default:
			return fmt.Errorf("generationConfig.%s не разрешён", k)
		}
	}
	return nil
}
