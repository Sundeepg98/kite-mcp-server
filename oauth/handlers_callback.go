package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
)

// --- Kite OAuth Callback ---

// HandleKiteOAuthCallback handles the Kite callback for MCP OAuth flow.
// Called when flow=oauth in the callback query params.
func (h *Handler) HandleKiteOAuthCallback(w http.ResponseWriter, r *http.Request, requestToken string) {
	if requestToken == "" {
		http.Error(w, "missing request_token", http.StatusBadRequest)
		return
	}

	signedData := r.URL.Query().Get("data")
	if signedData == "" {
		http.Error(w, "missing data parameter", http.StatusBadRequest)
		return
	}

	encodedState, err := h.signer.Verify(signedData)
	if err != nil {
		h.logger.Warn("Invalid OAuth callback signature", "error", err)
		http.Error(w, "invalid or expired callback data", http.StatusBadRequest)
		return
	}

	stateJSON, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		http.Error(w, "invalid state encoding", http.StatusBadRequest)
		return
	}
	var st oauthState
	if err := json.Unmarshal(stateJSON, &st); err != nil {
		http.Error(w, "invalid state data", http.StatusBadRequest)
		return
	}

	var mcpCode string
	var ssoEmail string
	if h.clients.IsKiteClient(st.ClientID) {
		// Per-user Kite API key: try immediate exchange for returning users (SSO),
		// fall back to deferred exchange for first-time users.
		var immediateOK bool
		if apiSecret, ok := h.exchanger.GetSecretByAPIKey(st.ClientID); ok {
			email, err := h.exchanger.ExchangeWithCredentials(requestToken, st.ClientID, apiSecret)
			if err != nil {
				// Credentials may be stale (user changed secret at Kite).
				// Fall through to deferred exchange — fresh secret from client will fix it.
				h.logger.Warn("Immediate exchange failed, falling back to deferred",
					"client_id", st.ClientID, "error", err)
			} else {
				immediateOK = true
				ssoEmail = email
				var genErr error
				mcpCode, genErr = h.authCodes.Generate(&AuthCodeEntry{
					ClientID:      st.ClientID,
					CodeChallenge: st.CodeChallenge,
					RedirectURI:   st.RedirectURI,
					Email:         email,
				})
				if genErr != nil {
					h.logger.Error("Failed to generate auth code (immediate)", "error", genErr)
					http.Error(w, "server error", http.StatusInternalServerError)
					return
				}
				h.logger.Info("Kite OAuth callback (immediate exchange, SSO)", "email", email, "client_id", st.ClientID)
			}
		}
		if !immediateOK {
			var err error
			mcpCode, err = h.authCodes.Generate(&AuthCodeEntry{
				ClientID:      st.ClientID,
				CodeChallenge: st.CodeChallenge,
				RedirectURI:   st.RedirectURI,
				RequestToken:  requestToken,
			})
			if err != nil {
				h.logger.Error("Failed to generate auth code (deferred)", "error", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			h.logger.Info("Kite OAuth callback (deferred exchange)", "client_id", st.ClientID)
		}
	} else if st.RegistryKey != "" {
		apiSecret := ""
		if h.registry != nil {
			if secret, ok := h.registry.GetSecretByAPIKey(st.RegistryKey); ok {
				apiSecret = secret
			}
		}
		if apiSecret == "" {
			h.logger.Error("Registry key not found in registry", "registry_key", st.RegistryKey)
			http.Error(w, "failed to authenticate: registry credentials not found", http.StatusInternalServerError)
			return
		}
		email, err := h.exchanger.ExchangeWithCredentials(requestToken, st.RegistryKey, apiSecret)
		if err != nil {
			h.logger.Error("Registry flow Kite token exchange failed", "registry_key", st.RegistryKey, "error", err)
			http.Error(w, "failed to authenticate with Kite", http.StatusInternalServerError)
			return
		}
		mcpCode, err = h.authCodes.Generate(&AuthCodeEntry{
			ClientID:      st.ClientID,
			CodeChallenge: st.CodeChallenge,
			RedirectURI:   st.RedirectURI,
			Email:         email,
		})
		if err != nil {
			h.logger.Error("Failed to generate auth code (registry)", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		ssoEmail = email
		h.logger.Info("Registry flow Kite OAuth complete", "email", email, "registry_key", st.RegistryKey[:8]+"...", "client_id", st.ClientID)
	} else {
		email, err := h.exchanger.ExchangeRequestToken(requestToken)
		if err != nil {
			h.logger.Error("Kite token exchange failed", "error", err)
			http.Error(w, "failed to authenticate with Kite", http.StatusInternalServerError)
			return
		}
		mcpCode, err = h.authCodes.Generate(&AuthCodeEntry{
			ClientID:      st.ClientID,
			CodeChallenge: st.CodeChallenge,
			RedirectURI:   st.RedirectURI,
			Email:         email,
		})
		if err != nil {
			h.logger.Error("Failed to generate auth code", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		ssoEmail = email
		h.logger.Debug("Kite OAuth complete, issuing MCP auth code", "email", email, "client_id", st.ClientID)
	}

	// SSO: set dashboard cookie if email is known (Callback Session Establishment pattern)
	if ssoEmail != "" {
		if err := h.SetAuthCookie(w, ssoEmail); err != nil {
			h.logger.Warn("Failed to set SSO dashboard cookie", "email", ssoEmail, "error", err)
		} else {
			h.logger.Debug("SSO dashboard cookie set", "email", ssoEmail)
		}

		// DPDP Act 2023 consent log: record a grant event now that we know
		// the email + request metadata. Best-effort — the recorder logs
		// its own errors; we don't fail the OAuth callback on log failures.
		// See kc/audit.ConsentRecorder wiring in app/wire.go.
		if h.consentRecorder != nil {
			h.consentRecorder(ssoEmail, clientIP(r), r.UserAgent())
		}
	}

	parsed, parseErr := url.Parse(st.RedirectURI)
	if parseErr != nil {
		h.logger.Error("Invalid redirect URI in state", "redirect_uri", st.RedirectURI, "error", parseErr)
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	params := parsed.Query()
	params.Set("code", mcpCode)
	if st.State != "" {
		params.Set("state", st.State)
	}
	redirectURL := (&url.URL{
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawQuery: params.Encode(),
	}).String()

	if h.loginSuccessTmpl == nil {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Title       string
		RedirectURL string
	}{
		Title:       "Login Successful",
		RedirectURL: redirectURL,
	}
	if err := h.loginSuccessTmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.logger.Error("Failed to render success template", "error", err)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
}
